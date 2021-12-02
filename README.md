# Automatic deployment of BAM and BDDS VMs for lab testing

1. Obtain Bluecat deployment files
The OVA, patches and updates are available at:
https://care.bluecatnetworks.com/s/article/DNS-Integrity-Released-GA-Patches

Get all of the base OVA, patches and updates and:
- move all OVA to the `ova` directory
- move all updates to the `updates` directory
- move all patches to the `patches` directory

2. Fetch yourself an existing BAM backup file to deploy (if any)
Put the backup file into `backups`.

3. Build bluecat_config.yaml
Copy sample_bluecat_config.yaml to ~/.bluecat_config.yaml and edit to your liking

4. Add X.509 cert for the BAM
Put into certs an `<fqdn>.crt` and `<fqdn>.key` that shall be deployed to BAM.

5. Add migration XML (if needed)
All migration XML go into `migration`.


# TODO:
- IPv6 routing
- IPv6 config of BAM
- only pushing relevant updates would be nice
- Server objects on BAM need to be dual-stacked (API needs to learn IPv6 first)
- Validation of deployed BDDS (reading zones from BAM and asking DNS/DHCP via service)
- deploying non-BDDS DNS secondary service(s) and ensure sync to DNS service
  (build the named.conf from BAM API)
- add backup schedule to BAM

Default logins: https://docs.bluecatnetworks.com/r/BlueCat-default-login-credentials/BlueCat-default-login-credentials
