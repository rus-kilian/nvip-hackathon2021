"""
Partially taken from Nathan Prziborowski
Github: https://github.com/prziborowski

That code is released under the terms of the Apache 2
http://www.apache.org/licenses/LICENSE-2.0.html
"""
import os
import ssl
import sys
import tarfile
import time
import datetime
import yaml
import json
import base64
import requests
import textwrap
from tqdm import tqdm
from tqdm.utils import CallbackIOWrapper

from threading import Timer
from typing import Iterable
from six.moves.urllib.request import (
    Request,
    urlopen,
    UnknownHandler,
    HTTPDefaultErrorHandler,
    HTTPRedirectHandler,
    HTTPSHandler,
    HTTPErrorProcessor,
    OpenerDirector,
    install_opener,
)
from six.moves.urllib.parse import urlencode, quote

from pyVmomi import vim, vmodl
from tools.toolbox.internals import (
    spinner,
    yellowprint,
    greenprint,
    redprint,
    blueprint,
    abort,
    statusprint,
    timeout_input,
)
from tools.toolbox.debian import remaster_iso
from tools.toolbox.internals import prompt_action
from colorama.ansi import clear_line


class SafeOpener(OpenerDirector):
    def __init__(self, handlers: Iterable = None):
        super().__init__()
        handlers = handlers or (
            UnknownHandler,
            HTTPDefaultErrorHandler,
            HTTPRedirectHandler,
            HTTPSHandler,
            HTTPErrorProcessor,
        )

        for handler_class in handlers:
            self.add_handler(handler_class())


def upload_ova(
    si,
    name,
    ova_path,
    host,
    dc=None,
    rp=None,
    ds=None,
    folder=None,
    ova_net=None,
    network=None,
    dvs_network=False,
):
    datacenter = dc
    if not isinstance(datacenter, vim.Datacenter):
        if dc:
            datacenter = get_dc(si, dc)
        else:
            datacenter = si.content.rootFolder.childEntity[0]

    resource_pool = rp
    if not isinstance(resource_pool, vim.ResourcePool):
        if rp:
            resource_pool = get_rp(si, datacenter, rp)
        else:
            resource_pool = get_largest_free_rp(si, datacenter)

    datastore = ds
    if not isinstance(datastore, vim.Datastore):
        if ds:
            datastore = get_ds(datacenter, ds)
        else:
            datastore = get_largest_free_ds(datacenter)

    vmFolder = folder
    if not isinstance(vmFolder, vim.Folder):
        if folder:
            vmFolder = get_folder(si, datacenter, folder)
        else:
            vmFolder = datacenter.vmFolder

    if ova_net and network:
        vmNet = get_network(si, datacenter, network, dvs_network)
        omnm = [vim.OvfManager.NetworkMapping(name=ova_net, network=vmNet)]
    else:
        omnm = None

    if not os.path.exists(ova_path):
        abort("No such OVA: '%s'" % ova_path)
    ovf_handle = OvfHandler(ova_path)

    ovf_manager = si.content.ovfManager
    # CreateImportSpecParams can specify many useful things such as
    # diskProvisioning (thin/thick/sparse/etc)
    # networkMapping (to map to networks)
    # propertyMapping (descriptor specific properties)
    cisp = vim.OvfManager.CreateImportSpecParams(entityName=name, networkMapping=omnm)
    cisr = ovf_manager.CreateImportSpec(
        ovf_handle.get_descriptor(), resource_pool, datastore, cisp
    )

    # These errors might be handleable by supporting the parameters in
    # CreateImportSpecParams
    if cisr.error:
        redprint("The following errors will prevent import of this OVA:")
        for error in cisr.error:
            print("%s" % error)
        return 1

    ovf_handle.set_spec(cisr)

    lease = resource_pool.ImportVApp(cisr.importSpec, vmFolder)
    while lease.state == vim.HttpNfcLease.State.initializing:
        spinner("Waiting for lease to be ready...")
        time.sleep(1)
    blueprint("\rLease initialized. Proceeding...    ")
    if lease.state == vim.HttpNfcLease.State.error:
        redprint("Lease error: %s" % lease.error)
        return 1
    if lease.state == vim.HttpNfcLease.State.done:
        return 0

    greenprint(clear_line() + "\rStarting deploy...")
    return ovf_handle.upload_disks(lease, host)


def get_dc(si, name):
    """
    Get a datacenter by its name.
    """
    for datacenter in si.content.rootFolder.childEntity:
        if datacenter.name == name:
            return datacenter
    raise Exception("Failed to find datacenter named %s" % name)


def get_rp(si, datacenter, name):
    """
    Get a resource pool in the datacenter by its names.
    """
    view_manager = si.content.viewManager
    container_view = view_manager.CreateContainerView(
        datacenter, [vim.ResourcePool], True
    )
    try:
        for resource_pool in container_view.view:
            if resource_pool.name == name:
                return resource_pool
    finally:
        container_view.Destroy()
    raise Exception(
        "Failed to find resource pool %s in datacenter %s" % (name, datacenter.name)
    )


def get_largest_free_rp(si, datacenter):
    """
    Get the resource pool with the largest unreserved memory for VMs.
    """
    view_manager = si.content.viewManager
    container_view = view_manager.CreateContainerView(
        datacenter, [vim.ResourcePool], True
    )
    largest_rp = None
    unreserved_for_vm = 0
    try:
        for resource_pool in container_view.view:
            if resource_pool.runtime.memory.unreservedForVm > unreserved_for_vm:
                largest_rp = resource_pool
                unreserved_for_vm = resource_pool.runtime.memory.unreservedForVm
    finally:
        container_view.Destroy()
    if largest_rp is None:
        raise Exception(
            "Failed to find a resource pool in datacenter %s" % datacenter.name
        )
    return largest_rp


def get_ds(datacenter, name):
    """
    Pick a datastore by its name.
    """
    for datastore in datacenter.datastore:
        try:
            if datastore.name == name:
                return datastore
        except Exception:
            abort(
                "error accessing datastore %s in datacenter %s"
                % (name, datacenter.name)
            )
    abort("Failed to find %s on datacenter %s" % (name, datacenter.name))


def get_largest_free_ds(datacenter):
    """
    Pick the datastore that is accessible with the largest free space.
    """
    largest = None
    largest_free = 0
    for datastore in datacenter.datastore:
        try:
            free_space = datastore.summary.freeSpace
            if free_space > largest_free and datastore.summary.accessible:
                largest_free = free_space
                largest = datastore
        except Exception:
            abort(
                "error accessing datastore %s in datacenter %s"
                % (datastore.name, datacenter.name)
            )
    if largest is None:
        raise Exception("Failed to find any free datastores on %s" % datacenter.name)
    return largest


def wait_for_tasks(si, tasks):
    """Given the service instance and tasks, it returns after all the
    tasks are complete
    """
    property_collector = si.content.propertyCollector
    task_list = [str(task) for task in tasks]
    # Create filter
    obj_specs = [vmodl.query.PropertyCollector.ObjectSpec(obj=task) for task in tasks]
    property_spec = vmodl.query.PropertyCollector.PropertySpec(
        type=vim.Task, pathSet=[], all=True
    )
    filter_spec = vmodl.query.PropertyCollector.FilterSpec()
    filter_spec.objectSet = obj_specs
    filter_spec.propSet = [property_spec]
    pcfilter = property_collector.CreateFilter(filter_spec, True)
    try:
        version, state = None, None
        # Loop looking for updates till the state moves to a completed state.
        while task_list:
            update = property_collector.WaitForUpdates(version)
            for filter_set in update.filterSet:
                for obj_set in filter_set.objectSet:
                    task = obj_set.obj
                    for change in obj_set.changeSet:
                        if change.name == "info":
                            state = change.val.state
                        elif change.name == "info.state":
                            state = change.val
                        else:
                            continue

                        if not str(task) in task_list:
                            continue

                        if state == vim.TaskInfo.State.success:
                            # Remove task from taskList
                            task_list.remove(str(task))
                        elif state == vim.TaskInfo.State.error:
                            raise task.info.error
            # Move to next version
            version = update.version
    finally:
        if pcfilter:
            pcfilter.Destroy()


def compile_folder_path_for_object(vobj):
    """ make a /vm/foo/bar/baz like folder path for an object """

    paths = []
    if isinstance(vobj, vim.Folder):
        paths.append(vobj.name)

    thisobj = vobj
    while hasattr(thisobj, "parent"):
        thisobj = thisobj.parent
        try:
            moid = thisobj._moId
        except AttributeError:
            moid = None
        # offset datacenter
        if moid in ["group-d1", "ha-folder-root"]:
            break
        if isinstance(thisobj, vim.Folder):
            paths.append(thisobj.name)
    paths.reverse()
    return "/" + "/".join(paths)


def get_folder(si, datacenter, name):
    """
    Pick a folder by its path.
    """
    view_manager = si.content.viewManager
    container_view = view_manager.CreateContainerView(datacenter, [vim.Folder], True)
    try:
        for folder in container_view.view:
            path = compile_folder_path_for_object(folder)
            if path == name:
                return folder
    finally:
        container_view.Destroy()
    raise Exception(
        "Failed to find folder %s in datacenter %s" % (name, datacenter.name)
    )


def get_network(si, datacenter, name, distributed):
    view_manager = si.content.viewManager
    try:
        if not distributed:
            container_view = view_manager.CreateContainerView(
                datacenter, [vim.Network], True
            )
            for net in container_view.view:
                if net.name == name:
                    return net
        else:
            container_view = view_manager.CreateContainerView(
                datacenter, [vim.DistributedVirtualSwitch], True
            )
            for dvs in container_view.view:
                for port_group in dvs.portgroup:
                    if name == port_group.name:
                        return port_group
    finally:
        container_view.Destroy()
    raise Exception(
        "Failed to find network %s in datacenter %s" % (name, datacenter.name)
    )


def get_vm(si, datacenter, name):
    try:
        view_manager = si.content.viewManager
        container_view = view_manager.CreateContainerView(
            datacenter, [vim.VirtualMachine], True
        )
        for vm in container_view.view:
            if vm.name == name:
                return vm
    finally:
        container_view.Destroy()
    raise Exception("Failed to find VM %s in datacenter %s" % (name, datacenter.name))


def list_vms(si, datacenter):
    vms = {}
    try:
        view_manager = si.content.viewManager
        container_view = view_manager.CreateContainerView(
            datacenter, [vim.VirtualMachine], True
        )
        for vm in container_view.view:
            vms[vm.name] = vm
    finally:
        container_view.Destroy()
    return vms


def get_all_vm_snapshots(vm, snapshots=None):
    found_snapshots = []

    if not vm.snapshot:
        return found_snapshots

    if not snapshots:
        snapshots = vm.snapshot.rootSnapshotList

    for snapshot in snapshots:
        if snapshot.childSnapshotList:
            found_snapshots += get_all_vm_snapshots(vm, snapshot.childSnapshotList)
        # XXX: if we wanted, we could also add the path and the description here...
        found_snapshots += [snapshot.name]
    return found_snapshots


def get_snapshots_by_name_recursively(snapshots, snapname):
    snap_obj = []
    for snapshot in snapshots:
        if snapshot.name == snapname:
            snap_obj.append(snapshot)
        else:
            snap_obj = snap_obj + get_snapshots_by_name_recursively(
                snapshot.childSnapshotList, snapname
            )
    return snap_obj


def get_current_snap_obj(snapshots, snapob):
    snap_obj = []
    for snapshot in snapshots:
        if snapshot.snapshot == snapob:
            snap_obj.append(snapshot)
        snap_obj = snap_obj + get_current_snap_obj(snapshot.childSnapshotList, snapob)
    return snap_obj


def snapshot_vm(
    si,
    vm,
    snapshot_name,
    description=str(datetime.datetime.now()),
    dumpMemory=True,
    quiesce=True,
):
    print("Snapshotting VM %s as '%s'..." % (vm.name, snapshot_name), end="")
    sys.stdout.flush()
    wait_for_tasks(
        si, [vm.CreateSnapshot(snapshot_name, description, dumpMemory, quiesce)]
    )
    greenprint(snapshot_name, prefix=(clear_line() + "\rCreated VM snapshot: "))


def revert_to_snapshot(si, vm, snapshot):
    blueprint("Reverting VM %s to snapshot %s" % (vm.name, snapshot))
    snap_obj = get_snapshots_by_name_recursively(vm.snapshot.rootSnapshotList, snapshot)
    if len(snap_obj) != 1:
        abort("Failed to access snapshot")
    snap_obj = snap_obj[0].snapshot
    wait_for_tasks(si, [snap_obj.RevertToSnapshot_Task()])
    greenprint("Done restoring VM %s to snapshot %s" % (vm.name, snapshot))


def deletedirectory(si, dc, path):
    d = si.content.fileManager.DeleteFile(path, dc)
    wait_for_tasks(si, [d])


def get_tarfile_size(tarfile):
    """
    Determine the size of a file inside the tarball.
    If the object has a size attribute, use that. Otherwise seek to the end
    and report that.
    """
    if hasattr(tarfile, "size"):
        return tarfile.size
    size = tarfile.seek(0, 2)
    tarfile.seek(0, 0)
    return size


def answer_vm_question(virtual_machine, choice=None):
    print("\n")
    choices = virtual_machine.runtime.question.choice.choiceInfo
    default_option = None
    if virtual_machine.runtime.question.choice.defaultIndex is not None:
        index = virtual_machine.runtime.question.choice.defaultIndex
        default_option = choices[index]
    while choice not in [o.key for o in choices]:
        yellowprint("VM power on is paused by this question:\n\n")
        print("\n".join(textwrap.wrap(virtual_machine.runtime.question.text, 60)))
        for option in choices:
            print("\t %s: %s " % (option.key, option.label))
        if default_option is not None:
            print("default (%s): %s\n" % (default_option.label, default_option.key))
        if choice is None:
            choice = input("\nchoice number: ").strip()  # nosec: B322
        print("...")
    return choice


def create_vm(
    vm_name,
    si,
    dc,
    vm_folder,
    datastore,
    net_name="VM Network",
    hddGB=16,
    RAM=2048,
    vCPUs=1,
    boot=False,
    resource_pool=None,
    dvs_network=False,
    guestId="debian10_64Guest",
):
    folder = get_folder(si, dc, vm_folder)
    rp = None
    if resource_pool:
        rp = get_rp(si, dc, resource_pool)
    else:
        rp = get_largest_free_rp(si, dc)
    _net = get_network(si, dc, net_name, dvs_network)

    devices = []
    datastore_path = "[" + datastore.name + "] " + vm_name
    vmx_file = vim.vm.FileInfo(
        logDirectory=None,
        snapshotDirectory=None,
        suspendDirectory=None,
        vmPathName=datastore_path,
    )

    nicspec = vim.vm.device.VirtualDeviceSpec()
    nicspec.operation = vim.vm.device.VirtualDeviceSpec.Operation.add
    nic_type = vim.vm.device.VirtualVmxnet3()
    nicspec.device = nic_type
    nicspec.device.deviceInfo = vim.Description()
    if dvs_network:
        dvs_port_connection = vim.dvs.PortConnection()
        dvs_port_connection.portgroupKey = _net.key
        dvs_port_connection.switchUuid = _net.config.distributedVirtualSwitch.uuid
        nicspec.device.backing = (
            vim.vm.device.VirtualEthernetCard.DistributedVirtualPortBackingInfo()
        )
        nicspec.device.backing.port = dvs_port_connection
    else:
        nicspec.device.backing = vim.vm.device.VirtualEthernetCard.NetworkBackingInfo()
        nicspec.device.backing.network = _net
        nicspec.device.backing.deviceName = _net.name
    nicspec.device.connectable = vim.vm.device.VirtualDevice.ConnectInfo()
    nicspec.device.connectable.startConnected = True
    nicspec.device.connectable.allowGuestControl = True
    devices.append(nicspec)

    scsi_ctr = vim.vm.device.VirtualDeviceSpec()
    scsi_ctr.operation = vim.vm.device.VirtualDeviceSpec.Operation.add
    scsi_ctr.device = vim.vm.device.ParaVirtualSCSIController()
    scsi_ctr.device.deviceInfo = vim.Description()
    scsi_ctr.device.slotInfo = vim.vm.device.VirtualDevice.PciBusSlotInfo()
    scsi_ctr.device.slotInfo.pciSlotNumber = 16
    scsi_ctr.device.controllerKey = 100
    scsi_ctr.device.unitNumber = 3
    scsi_ctr.device.busNumber = 0
    scsi_ctr.device.hotAddRemove = True
    scsi_ctr.device.sharedBus = "noSharing"
    scsi_ctr.device.scsiCtlrUnitNumber = 7
    devices.append(scsi_ctr)

    unit_number = 0
    controller = scsi_ctr.device
    disk_spec = vim.vm.device.VirtualDeviceSpec()
    disk_spec.fileOperation = "create"
    disk_spec.operation = vim.vm.device.VirtualDeviceSpec.Operation.add
    disk_spec.device = vim.vm.device.VirtualDisk()
    disk_spec.device.backing = vim.vm.device.VirtualDisk.FlatVer2BackingInfo()
    disk_spec.device.backing.diskMode = "persistent"
    disk_spec.device.backing.fileName = "[%s] %s/%s.vmdk" % (
        datastore.name,
        vm_name,
        vm_name,
    )
    disk_spec.device.unitNumber = unit_number
    disk_spec.device.capacityInKB = hddGB * 1024 * 1024
    disk_spec.device.controllerKey = controller.key
    devices.append(disk_spec)

    # guestId as per https://www.vmware.com/support/orchestrator/doc/vro-vsphere65-api/html/VcVirtualMachineGuestOsIdentifier.html
    # version by default is latest
    config = vim.vm.ConfigSpec(
        name=vm_name,
        memoryMB=int(RAM),
        numCPUs=int(vCPUs),
        files=vmx_file,
        guestId=guestId,
        version=None,
        deviceChange=devices,
    )
    task = folder.CreateVM_Task(config=config, pool=rp)
    wait_for_tasks(si, [task])

    vms = folder.childEntity
    vm = None
    for _vm in vms:
        if not ((hasattr(_vm, "childEntity")) or (isinstance(_vm, vim.VirtualApp))):
            if (_vm.runtime.powerState != vim.VirtualMachinePowerState.poweredOn) and (
                _vm.name == vm_name
            ):
                vm = _vm
                if boot:
                    task = _vm.PowerOn()
                    wait_for_tasks(si, [task])
    return vm


def create_vm_from_iso(
    hostname,
    domain,
    netinst_iso,
    si,
    dc,
    ds,
    server,
    folder,
    network,
    ipaddress,
    netmask,
    gateway,
    root_pwhash,
    dvs_network=False,
    add_packages=None,
):
    vms = list_vms(si, dc)
    if hostname in vms:
        vm = vms[hostname]
        snapshots = get_all_vm_snapshots(vm)
        if snapshots:
            greenprint("Found existing VM with snapshots!")
            snapshot = prompt_action(snapshots, "snapshot")
            if snapshot:
                revert_to_snapshot(si, vm, snapshot)
                return
        else:
            yellowprint("Found existing VM!")
        _ans = timeout_input("Delete and redeploy?", hint="(Y/n)")
        if not _ans or _ans.lower() != "n":
            yellowprint("Shutting down and removing to restart deployment")
            vm.PowerOff()
            vm.Destroy()
            timeout_input("Cleanup pending - waiting 10s for storage to sync", 10)
        else:
            return vm
    vm = create_vm(
        hostname,
        si,
        dc,
        folder,
        ds,
        network,
        dvs_network=dvs_network,
    )
    dspath = vm.summary.config.vmPathName
    _vmx = os.path.basename(dspath)
    _ds_name = vm.datastore[0].info.name
    _ds_offset = "[%s] " % _ds_name
    if not dspath.startswith(_ds_offset):
        abort("Unknown datastore path: %s" % dspath)
    _vmpath = dspath[len(_ds_offset) : -(len(_vmx) + 1)]  # noqa: E203

    _preseed_iso = remaster_iso(
        netinst_iso,
        ipaddress,
        netmask,
        gateway,
        hostname.replace("." + domain, ""),
        root_pwhash,
        domain=domain,
        add_packages=add_packages,
    )
    if not _preseed_iso:
        abort("Failed to generate preseeded installer ISO!")
    _vm_iso = _vmpath + "/" + os.path.basename(_preseed_iso)

    statusprint("Uploading preseeded ISO to datastore")
    upload_file(
        si,
        dc,
        ds,
        server,
        _preseed_iso,
        _vm_iso,
    )
    statusprint("Adding ISO as CD rom")
    cdrom = mount_iso(si, vm, _vm_iso, dc, ds)
    statusprint("CD added. Starting installer")
    boot_vm(vm)
    timeout = 1800
    timeout_step = 1
    _success = False
    for _t in range(timeout, 0, -timeout_step):
        statusprint("Waiting for installer to finish [%ds]" % _t)
        if vm.guest.toolsRunningStatus == "guestToolsRunning":
            if vm.guest.ipAddress is not None:
                _success = True
                break
        time.sleep(timeout_step)
    if not _success:
        abort("VM installed hasn't completed!")
    # fetching the actual cdrom backing of the running VM
    cdrom = iso_is_mounted(vm, ds, _vm_iso)
    statusprint("Installer complete. Unmounting ISO")
    shutdown_vm(vm)
    umount_cdrom(si, vm, cdrom)
    cdrom = iso_is_mounted(vm, ds, _vm_iso)
    deletedirectory(si, dc, "[%s]/%s" % (_ds_name, _vm_iso))
    if os.path.exists(_preseed_iso):
        os.unlink(_preseed_iso)
    boot_vm(vm)
    _success = False
    timeout = 60
    for _t in range(timeout, 0, -timeout_step):
        statusprint("Waiting for VM to finish booting [%ds remaining]" % _t)
        if vm.guest.toolsRunningStatus == "guestToolsRunning":
            if vm.guest.ipAddress is not None:
                _success = True
                break
        time.sleep(timeout_step)
    statusprint()
    if not _success:
        abort("VM didn't boot after install?!")
    greenprint("Done preparing VM '%s'" % vm.name)
    res = timeout_input("Snapshot VM before proceeding?", hint="(Y/n)")
    if res != "n":
        snapshot_vm(
            si,
            vm,
            os.path.basename(netinst_iso),
            "Netinstaller ISO preseeded\nAdditional packages:\n" + str(add_packages),
        )


def reboot_vm(vm):
    if vm.runtime.powerState == vim.VirtualMachinePowerState.poweredOn:
        if vm.guest.toolsRunningStatus == "guestToolsRunning":
            print("Trying reboot using vmware tools")
            vm.RebootGuest()
        else:
            redprint("No VMware Tools running. Resetting hard.")
            vm.ResetVM_Task()
    else:
        yellowprint("VM isn't running - can't reboot. Booting now")
        boot_vm(vm)


def shutdown_vm(vm, timeout=1800):
    if vm.runtime.powerState == vim.VirtualMachinePowerState.poweredOn:
        if vm.guest.toolsRunningStatus == "guestToolsRunning":
            statusprint("Shutting down %s using VMware tools" % vm.name)
            vm.ShutdownGuest()
            for t in range(1, timeout):
                if vm.runtime.powerState == vim.VirtualMachinePowerState.poweredOn:
                    statusprint(
                        "Waiting for shutdown to complete (%d/%d)..." % (t, timeout)
                    )
                    time.sleep(1)
                else:
                    break
            if vm.runtime.powerState == vim.VirtualMachinePowerState.poweredOn:
                statusprint()
                yellowprint("Timeout! Soft shutdown did not complete. Powering off.")
                vm.PowerOff()
            greenprint("Shutdown complete!")
        else:
            yellowprint("No VMware Tools running. Powering off.")
            vm.PowerOff()
    else:
        greenprint("VM isn't running")


def boot_vm(vm):
    if vm.runtime.powerState == vim.VirtualMachinePowerState.poweredOn:
        yellowprint("Maching is already running?")
    else:
        statusprint("Booting VM")
        task = vm.PowerOn()
        answers = {}
        while task.info.state not in [
            vim.TaskInfo.State.success,
            vim.TaskInfo.State.error,
        ]:

            # we'll check for a question, if we find one, handle it,
            # Note: question is an optional attribute and this is how pyVmomi
            # handles optional attributes. They are marked as None.
            if vm.runtime.question is not None:
                question_id = vm.runtime.question.id
                if question_id not in answers.keys():
                    answers[question_id] = answer_vm_question(vm, "")
                    vm.AnswerVM(question_id, answers[question_id])

            # create a spinning cursor so people don't kill the script...
            spinner("Booting VM:" + task.info.state)

        if task.info.state == vim.TaskInfo.State.error:
            # some vSphere errors only come with their class and no other message
            print("error type: %s" % task.info.error.__class__.__name__)
            print("found cause: %s" % task.info.error.faultCause)
            for fault_msg in task.info.error.faultMessage:
                print(fault_msg.key)
                print(fault_msg.message)
            sys.exit(-1)
    greenprint(clear_line() + "\rVM %s is now booted up" % vm.name)


def update_cloudinit(si, vm, metadata, userdata):
    print("Checking cloud-init guest info data")
    try:
        md = json.loads(metadata)
    except Exception:
        try:
            md = yaml.safe_load(metadata)
        except Exception:
            abort("Invalid data for metadata - neither JSON nor YAML!")
    try:
        ud = yaml.safe_load(userdata)
    except Exception:
        abort("Invalid YAML for userdata!\n-------\n%s\n-------" % userdata)
    # Ensure cloud-config prefix in YAML
    if not userdata.startswith("#cloud-config\n"):
        userdata = "#cloud-config\n" + userdata
    # print(userdata)
    cspec = vim.vm.ConfigSpec()
    md = str(base64.b64encode(metadata.encode("utf-8")), "utf-8")
    ud = str(base64.b64encode(userdata.encode("utf-8")), "utf-8")
    _md_match = False
    _ud_match = False
    for option in vm.config.extraConfig:
        if option.key == "guestinfo.cloudinit.metadata":
            if option.value == md:
                greenprint("metadata matches")
                _md_match = True
            else:
                yellowprint("metadata needs update!")
        if option.key == "guestinfo.cloudinit.userdata":
            if option.value == ud:
                greenprint("userdata matches")
                _ud_match = True
            else:
                yellowprint("userdata needs update!")
    if _md_match and _ud_match:
        greenprint("Cloud-init data matches already!")
        return False
    cspec.extraConfig = [
        vim.option.OptionValue(key="guestinfo.cloudinit.metadata", value=md),
        vim.option.OptionValue(key="guestinfo.cloudinit.userdata", value=ud),
    ]
    vm.Reconfigure(cspec)
    # task = vm.ReconfigVM_Task(cspec)
    # wait_for_tasks(si, [task])
    # print(vm.summary)
    yellowprint("Cloud-init updated!")
    return True


# Returns the first cdrom if any, else None.
def get_physical_cdrom(host):
    for lun in host.configManager.storageSystem.storageDeviceInfo.scsiLun:
        if lun.lunType == "cdrom":
            return lun
    return None


def find_free_ide_controller(vm):
    for dev in vm.config.hardware.device:
        if isinstance(dev, vim.vm.device.VirtualIDEController):
            # If there are less than 2 devices attached, we can use it.
            if len(dev.device) < 2:
                return dev
    return None


def find_device(vm, device_type):
    result = []
    for dev in vm.config.hardware.device:
        if isinstance(dev, device_type):
            result.append(dev)
    if len(result) > 0:
        return result


def new_cdrom_spec(controller_key, backing):
    connectable = vim.vm.device.VirtualDevice.ConnectInfo()
    connectable.allowGuestControl = True
    connectable.startConnected = True

    cdrom = vim.vm.device.VirtualCdrom()
    cdrom.controllerKey = controller_key
    cdrom.key = -1
    cdrom.connectable = connectable
    cdrom.backing = backing
    return cdrom


def iso_is_mounted(vm, ds, iso):
    iso_filename = "[%s] %s" % (ds.name, iso)
    statusprint("Checking whether '%s' is mounted on VM %s" % (iso_filename, vm.name))
    backing = vim.vm.device.VirtualCdrom.IsoBackingInfo(
        fileName=iso_filename, datastore=ds
    )
    cdroms = find_device(vm, vim.vm.device.VirtualCdrom)
    if cdroms:
        try:
            cdrom = next(
                filter(
                    lambda x: type(x.backing) == type(backing)
                    and x.backing.fileName == iso_filename,
                    cdroms,
                )
            )
        except StopIteration:
            print("None found!")
            return None
        return cdrom


def mount_iso(si, vm, iso, dc, ds):
    iso_filename = "[%s] %s" % (ds.name, iso)
    backing = vim.vm.device.VirtualCdrom.IsoBackingInfo(
        fileName=iso_filename, datastore=ds
    )
    cdrom = iso_is_mounted(vm, ds, iso)
    if cdrom:
        greenprint("ISO is already mounted!")
        return cdrom
    controller = find_free_ide_controller(vm)
    if controller is None:
        raise Exception("Failed to find a free slot on the IDE controller")
    else:
        statusprint("Found CD-Rom controller")

    cdroms = find_device(vm, vim.vm.device.VirtualCdrom)
    cdrom_operation = vim.vm.device.VirtualDeviceSpec.Operation
    device_spec = vim.vm.device.VirtualDeviceSpec()
    if cdroms is None:  # add a cdrom
        statusprint("Adding a CD-ROM device")
        cdrom = new_cdrom_spec(controller.key, backing)
        device_spec.operation = cdrom_operation.add
    else:  # edit an existing cdrom
        statusprint(
            "Found %d virtual CD-rom devices. Altering the existing CD-ROM device"
            % len(cdroms)
        )
        cdrom = cdroms.pop()
        cdrom.backing = backing
        device_spec.operation = cdrom_operation.edit
    cdrom.backing.datastore = ds
    cdrom.connectable = vim.vm.device.VirtualDevice.ConnectInfo()
    cdrom.connectable.startConnected = True
    cdrom.connectable.connected = True
    device_spec.device = cdrom
    config_spec = vim.vm.ConfigSpec(deviceChange=[device_spec])
    # print(device_spec)
    # print(config_spec)
    task = vm.ReconfigVM_Task(config_spec)
    wait_for_tasks(si, [task])
    greenprint(clear_line() + "\rISO mounted as virtual CD rom")

    if vm.runtime.powerState == vim.VirtualMachinePowerState.poweredOn:
        return iso_is_mounted(vm, ds, iso)


def umount_cdrom(si, vm, cdrom):
    if cdrom is not None:
        device_spec = vim.vm.device.VirtualDeviceSpec()
        device_spec.device = cdrom
        cdrom_operation = vim.vm.device.VirtualDeviceSpec.Operation
        device_spec.operation = cdrom_operation.remove
        config_spec = vim.vm.ConfigSpec(deviceChange=[device_spec])
        task = vm.ReconfigVM_Task(config_spec)
        wait_for_tasks(si, [task])


def upload_file(
    si,
    dc,
    ds,
    host,
    local_path,
    remote_path,
    verify_cert="/etc/ssl/certs/ca-certificates.crt",
    resource_type="folder",
):
    try:
        # Build the url to put the file - https://hostname:port/resource?params
        if not remote_path.startswith("/"):
            remote_file = "/" + remote_path
        else:
            remote_file = remote_path
        resource = "/" + resource_type + quote(remote_file)
        params = dict(dsName=ds.info.name)
        params["dcPath"] = dc.name.replace("&", "%26")
        params = urlencode(params)
        http_url = "https://" + host + ":443" + resource + "?" + params

        # Get the cookie built from the current session
        client_cookie = si._stub.cookie
        # Break apart the cookie into it's component parts - This is more than
        # is needed, but a good example of how to break apart the cookie
        # anyways. The verbosity makes it clear what is happening.
        cookie_name = client_cookie.split("=", 1)[0]
        cookie_value = client_cookie.split("=", 1)[1].split(";", 1)[0]
        cookie_path = (
            client_cookie.split("=", 1)[1].split(";", 1)[1].split(";", 1)[0].lstrip()
        )
        cookie_text = " " + cookie_value + "; $" + cookie_path
        # Make a cookie
        cookie = dict()
        cookie[cookie_name] = cookie_text

        # Get the request headers set up
        headers = {"Content-Type": "application/octet-stream"}

        # Get the file to upload ready, extra protection by using with against
        # leaving open threads
        file_size = os.stat(local_path).st_size
        with open(local_path, "rb") as file_data:
            # Connect and upload the file
            with tqdm(
                total=file_size, unit="B", unit_scale=True, unit_divisor=1024
            ) as t:
                wrapped_file = CallbackIOWrapper(t.update, file_data, "read")
                res = requests.put(
                    http_url,
                    params=params,
                    data=wrapped_file,
                    headers=headers,
                    cookies=cookie,
                    verify=verify_cert,
                )
        if res.status_code > 201 or res.status_code < 200:
            redprint("Got http server status: %d" % res.status_code)
            redprint(res.content.decode("utf-8"))
            abort("Upload failed!")
        else:
            greenprint("Uploaded the file")

    except vmodl.MethodFault as ex:
        abort("Caught vmodl fault : " + ex.msg)


def delete_file(si, dc, ds, remote_path):
    remote_file = "[%s] %s" % (ds.name, remote_path)
    # vim.vm.DeleteDatastoreFile_Task(remote_file)
    wait_for_tasks(si.content.fileManager.DeleteFile(remote_file, dc))


class OvfHandler(object):
    """
    OvfHandler handles most of the OVA operations.
    It processes the tarfile, matches disk keys to files and
    uploads the disks, while keeping the progress up to date for the lease.
    """

    def __init__(self, ovafile):
        """
        Performs necessary initialization, opening the OVA file,
        processing the files and reading the embedded ovf file.
        """
        self.handle = self._create_file_handle(ovafile)
        self.tarfile = tarfile.open(fileobj=self.handle)
        ovffilename = list(
            filter(lambda x: x.endswith(".ovf"), self.tarfile.getnames())
        )[0]
        ovffile = self.tarfile.extractfile(ovffilename)
        self.descriptor = ovffile.read().decode()

    def _create_file_handle(self, entry):
        """
        A simple mechanism to pick whether the file is local or not.
        This is not very robust.
        """
        if os.path.exists(entry):
            return FileHandle(entry)
        return WebHandle(entry)

    def get_descriptor(self):
        return self.descriptor

    def set_spec(self, spec):
        """
        The import spec is needed for later matching disks keys with
        file names.
        """
        self.spec = spec

    def get_disk(self, file_item):
        """
        Does translation for disk key to file name, returning a file handle.
        """
        ovffilename = list(
            filter(lambda x: x == file_item.path, self.tarfile.getnames())
        )[0]
        return self.tarfile.extractfile(ovffilename)

    def get_device_url(self, file_item, lease):
        for device_url in lease.info.deviceUrl:
            if device_url.importKey == file_item.deviceId:
                return device_url
        raise Exception("Failed to find deviceUrl for file %s" % file_item.path)

    def upload_disks(self, lease, host):
        """
        Uploads all the disks, with a progress keep-alive.
        """
        self.lease = lease
        try:
            self.start_timer()
            for fileItem in self.spec.fileItem:
                self.upload_disk(fileItem, lease, host)
            lease.Complete()
            greenprint("Finished deploy successfully.")
            return 0
        except vmodl.MethodFault as ex:
            redprint("Hit an error in upload: %s" % ex)
            lease.Abort(ex)
        except Exception as ex:
            redprint("Lease: %s" % lease.info)
            redprint("Hit an error in upload: %s" % ex)
            lease.Abort(vmodl.fault.SystemError(reason=str(ex)))
        return 1

    def upload_disk(self, file_item, lease, host):
        """
        Upload an individual disk. Passes the file handle of the
        disk directly to the urlopen request.
        """
        ovffile = self.get_disk(file_item)
        if ovffile is None:
            return
        device_url = self.get_device_url(file_item, lease)
        url = device_url.url.replace("*", host)
        headers = {"Content-length": get_tarfile_size(ovffile)}
        if hasattr(ssl, "_create_unverified_context"):
            ssl_context = ssl._create_unverified_context()  # nosec: B323
        else:
            ssl_context = None
        req = Request(url, ovffile, headers)
        opener = SafeOpener()
        install_opener(opener)
        urlopen(req, context=ssl_context)  # nosec: B310

    def start_timer(self):
        """
        A simple way to keep updating progress while the disks are transferred.
        """
        Timer(5, self.timer).start()

    def timer(self):
        """
        Update the progress and reschedule the timer if not complete.
        """
        try:
            prog = self.handle.progress()
            self.lease.Progress(prog)
            if self.lease.state not in [
                vim.HttpNfcLease.State.done,
                vim.HttpNfcLease.State.error,
            ]:
                self.start_timer()
            sys.stderr.write("Progress: %d%%\r" % prog)
        except Exception:  # nosec: B110 - Any exception means we should stop updating progress.
            pass


class FileHandle(object):
    def __init__(self, filename):
        self.filename = filename
        self.fh = open(filename, "rb")

        self.st_size = os.stat(filename).st_size
        self.offset = 0

    def __del__(self):
        self.fh.close()

    def tell(self):
        return self.fh.tell()

    def seek(self, offset, whence=0):
        if whence == 0:
            self.offset = offset
        elif whence == 1:
            self.offset += offset
        elif whence == 2:
            self.offset = self.st_size - offset

        return self.fh.seek(offset, whence)

    def seekable(self):
        return True

    def read(self, amount):
        self.offset += amount
        result = self.fh.read(amount)
        return result

    # A slightly more accurate percentage
    def progress(self):
        return int(100.0 * self.offset / self.st_size)


class WebHandle(object):
    def __init__(self, url):
        self.url = url
        opener = SafeOpener()
        install_opener(opener)
        r = urlopen(url)  # nosec: B310
        if r.code != 200:
            raise FileNotFoundError(url)
        self.headers = self._headers_to_dict(r)
        if "accept-ranges" not in self.headers:
            raise Exception("Site does not accept ranges")
        self.st_size = int(self.headers["content-length"])
        self.offset = 0

    def _headers_to_dict(self, r):
        result = {}
        if hasattr(r, "getheaders"):
            for n, v in r.getheaders():
                result[n.lower()] = v.strip()
        else:
            for line in r.info().headers:
                if line.find(":") != -1:
                    n, v = line.split(": ", 1)
                    result[n.lower()] = v.strip()
        return result

    def tell(self):
        return self.offset

    def seek(self, offset, whence=0):
        if whence == 0:
            self.offset = offset
        elif whence == 1:
            self.offset += offset
        elif whence == 2:
            self.offset = self.st_size - offset
        return self.offset

    def seekable(self):
        return True

    def read(self, amount):
        start = self.offset
        end = self.offset + amount - 1
        req = Request(self.url, headers={"Range": "bytes=%d-%d" % (start, end)})
        opener = SafeOpener()
        install_opener(opener)
        r = urlopen(req)  # nosec: B310
        self.offset += amount
        result = r.read(amount)
        r.close()
        return result

    # A slightly more accurate percentage
    def progress(self):
        return int(100.0 * self.offset / self.st_size)
