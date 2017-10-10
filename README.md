# watts_plugin_ca
A simple self signed certificate authority for WaTTS

The plugin supports the following configuration options:
- ca_path: The path of the directory where all the files will be stored needed to run the CA. The directory (including sub directories) will be created at the first run and the CA will be initialized. Please *DO NOT* create the directory beforehand. Ensure that watts has read and write permissions at the existing parent directory, as a directory and files need to be created.
- issuer_mapping: a JSON Object containing a mapping from the Issuer url to a short name, for more details see below.
- cert_valid_duration: This setting determines the lifetime of a certificate in days (default: 11)
- ca_subject: The subject of the CA, default is '/C=EU/O=INDIGO/OU=WATTS/CN=WATTS-CA'

## CA Subject
The CA Subject must be a valid certificate subject and must end in one CN.

## Issuer Mapping
The Issuer Mapping is a *SINGLE* line in the config file, containing a JSON object with
`key`/`value` pairs.

Each `key` is the url of an OpenID Connect provider supported by the service
using this plugin.
 - The url of the provider *MUST NOT* end in a slash as they are stripped from the incomming url
within the plugin.

The `value` is a short name for the provider.
 - the purpose is to limit the amount of characters used within the certificate subject, to keep it below the 64 character boundary.

Example:
```
# The following is WRONG as the keys have trailing slashes
{"https://iam-test.indigo-datacloud.eu/":"indigo-iam-test", "https://accounts.google.com/":"google"}
# the key-urls have no trailing slash, so the following is correct
{"https://iam-test.indigo-datacloud.eu":"indigo-iam-test", "https://accounts.google.com":"google"}
```

## Example Configuration
```
service.x509.description = A simple demo CA
service.x509.credential_limit = 3
service.x509.connection.type = local
service.x509.parallel_runner = 1
service.x509.authz.allow.any.sub.any = true
# the following line specifies this plugin
service.x509.cmd = /var/lib/watts/plugins/x509.py
# the next lines are the parameter to the plugin
service.x509.plugin.ca_path = /var/lib/watts/simple_ca
service.x509.plugin.ca_subject = /C=DE/O=KIT/OU=SCC/OU=WATTS/CN=WATTS-CA
service.x509.plugin.cert_valid_duration = 9
service.x509.plugin.issuer_mapping = {"https://iam-test.indigo-datacloud.eu":"indigo-iam-test"}
```

# Changelog
## Version 1.1.0
Introduce setting 'ca_subject'.

### Upgrading from 1.0.0 to 1.1.0
please create a file, relative to the ca_path named './private/cert_prefix'.
The content of the file needs to be:
```
/C=EU/O=INDIGO/OU=TTS
```
The new setting 'ca_subject' can be ignored.

## Version 1.0.0
The first well documented version
