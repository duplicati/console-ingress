# DuplicatiIngress

The ingress server for the Duplicati portal.

## Flow

The ingress server depends on knowing what organization a backup report is for. This can be either via the preconfigured tokens or via the JWT tokens.

For preconfigured tokens, a pre-made JSON file with a dictionary of token/orgid entries is loaded on startup and kept in memory.

For JWT tokens, the token is signed with a pre-shared key between the portal and the ingress server, and the tokens contains the orgId.

Once the organization is recognized, the file is parsed to validate that it is valid JSON and has some signature fields included.

If the tests pass, the file is encrypted with a key. The keyId can either be provided with the preconfigured tokens or extracted from the JWT.

The encrypted file is uploaded to the remote storage (S3 compatible, local filesystem or Postgre) and an event is published to mass transit, informing of the new file.

The ingress server is intended to have very few moving parts and generally just authorize & validate the input, and then store in persistent storage.

---

## Required environment variables

| Variable                      | Description                                                           |
| ----------------------------- | --------------------------------------------------------------------- |
| ENVIRONMENT\_\_ISPROD         | Production environment flag (false indicates development environment) |
| ENVIRONMENT\_\_STORAGE        | KVPSButter connection string for report storage                       |
| MESSAGING\_\_CONNECTIONSTRING | PostgreSQL connection string for connecting to the message bus        |
| ENCRYPTIONKEY\_\_???          | One or more encryption keys for encrypting backup reports             |
| INGRESS\_\_JWT\_\_AUTHORITY   | The authority that issued the JWT token (must match issuer config)    |
| INGRESS\_\_JWT\_\_AUDIENCE    | The audience for the JWT token (must match issuer config)             |
| INGRESS\_\_JWT\_\_SIGNINGKEY  | The signing key for the JWT token (must match issuers config)         |

## Optional environment variables

The following environment variables are optional, and should be considered for a production deployment:

| Variable                         | Description                                                                   |
| -------------------------------- | ----------------------------------------------------------------------------- |
| ENVIRONMENT\_\_HOSTNAME          | The server hostname for logging purposes                                      |
| ENVIRONMENT\_\_MACHINENAME       | Name of the machine for logging purposes                                      |
| ENVIRONMENT\_\_REDIRECTURL       | Url to redirect to when visiting the root path                                |
| PRECONFIGUREDTOKENS\_\_STORAGE   | The KVPSButter connection string to the storage that contains an IP blacklist |
| PRECONFIGUREDTOKENS\_\_WHITELIST | The key that contains the IP blacklist                                        |
| PRECONFIGUREDTOKENS\_\_BLACKLIST | The key that contains the IP blacklist                                        |

## Setting Up Local Development Environment

This project uses environment variables to configure the application during startup.

The provided [`launch.json`](./.vscode/launch.json) is configured to start without additional configuration, but does not integrate with a message bus, but instead uses a simple in-memory bus to simulate functionality.

If you need to debug with a message bus, you need to configure the connection string.

### Configure local environment for a message bus

It is recommeded that you configure variables by creating a [`local.environmentvariables.json`](./local.environmentvariables.json) file in the root of the project. This file is excluded from Git and Docker, making it less likely that you accidentally leak test variables.

This file:

- Should contain key-value pairs representing environment variables.
- Is loaded early during application startup.
- **Overrides any existing environment variables** if a key already exists.

This allows you to **locally customize** or **override** variables — without modifying the original configuration.

Example `local.environmentvariables.json` for using a local Postgre database:

```json
{
  "MESSAGING__CONNECTIONSTRING": "User ID=postgres;Password=*******;Host=localhost;Port=5432;Database=messaging;",
  "PRECONFIGUREDTOKENS__STORAGE": "file:///path/to/shared/folder?pathmapped=true"
}
```
