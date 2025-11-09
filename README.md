# Checkmk Plugin: Microsoft Entra Special Agent 

The **Microsoft Entra** Special Agent is an extension for the monitoring software **Checkmk**.  
It can be integrated into Checkmk 2.3 or newer.

You can download the extension package as an `.mkp` file from the [releases](../../releases) in this repository and upload it directly to your Checkmk site.  
See the Checkmk [documentation](https://docs.checkmk.com/latest/en/mkps.html) for details.

## Plugin Information

The Plugin provides monitoring for the following components:
- Microsoft Entra App Proxy Certificates
- Microsoft Entra App Registration Credentials
- Microsoft Entra CA VPN Certificate
- Microsoft Entra Connect/Cloud Sync
- Microsoft Entra SAML Certificates

See [Check Details](#check-details) for more information.

## Prerequisites

This Special Agent uses the Microsoft Graph API to collect the monitoring data.  
To access the API, you need a Microsoft Entra tenant and a Microsoft Entra app registration with a client secret ([Steps to Get It Working](#steps-to-get-it-working)).

You need at least the following API **application** permissions for your app registration to use all the checks:
- *Application.Read.All*
- *Directory.Read.ALl*
- *Organization.Read.All*

For a more granular options, the required API permissions per check are listed in the next sections.

To activate the checks, you must configure the **Microsoft Entra** Special Agent in Checkmk.
You will need the Microsoft Entra tenant ID, the App ID and the client secret from the Microsoft Entra app registration.
When you configure the Special Agent, you have the option to select only the services that you want to monitor. You do not have to implement all the checks, but at least one of them.

> [!NOTE]
> This plugin uses HTTPS connections to Microsoft.
>Make sure you have enabled **Trust system-wide configured CAs** or uploaded the CA certificates for the Microsoft domains in Checkmk.
>You can find these options in **Setup** > **Global settings** > **Trusted certificate authorities for SSL** under **Site management**.
>If your system does not trust the certificate you will encounter the error: `certificate verify failed: unable to get local issuer certificate`.
>
>Also do not block the communications to:
>- https://login.microsoftonline.com
>- https://graph.microsoft.com

## Check Details

### Microsoft Entra App Proxy Certificates

#### Description

This check monitors the expiration time of custom certificates from Entra app proxies.

#### Checkmk Service Example

<img width="1064" height="59" alt="grafik" src="https://github.com/user-attachments/assets/6d580262-d010-4a71-815b-fedd984bd1e6" />

#### Checkmk Parameters

1. **Certificate expiration**: Specify the lower levels for the Microsoft Entra app proxy certificates expiration time. The default values are 14 days (WARN) and 5 days (CRIT). To ignore the certificate expiration, select "No levels".

#### Microsoft Graph API

**API Permissions**: At least *Directory.Read.All* (Application permission)

**Endpoints**: `https://graph.microsoft.com/beta/applications`, `https://graph.microsoft.com/v1.0/servicePrincipals`

---

### Microsoft Entra App Registration Credentials

#### Description

This check monitors the expiration time of secrets and certificates from Entra app registrations.

#### Checkmk Service Example

![grafik](https://github.com/user-attachments/assets/72493199-730c-4dbf-8d4d-d09e8e343ff4)

#### Checkmk Parameters

1. **Credential expiration**: Specify the lower levels for the Microsoft Entra app credential expiration time. The default values are 14 days (WARN) and 5 days (CRIT). To ignore the credential expiration, select "No levels".
2. **Exclude credentials**: Specify a list of credential descriptions that you do not want to monitor.

#### Microsoft Graph API

**API Permissions**: At least *Application.Read.All* (Application permission)

**Endpoint**: `https://graph.microsoft.com/v1.0/applications`

---

### Microsoft Entra CA VPN Certificates

#### Description

This check monitors the expiration time of the Entra Conditional Access VPN certificate.

#### Checkmk Service Example

![grafik](https://github.com/user-attachments/assets/535a3a57-1290-4c17-b567-a34c7c5d8bd3)

#### Checkmk Parameters

1. **Certificate expiration**: Specify the lower levels for the Microsoft Entra Conditional Access VPN certificate expiration time. The default values are 14 days (WARN) and 5 days (CRIT). To ignore the certificate expiration, select "No levels".

#### Microsoft Graph API

**API Permissions**: At least *Application.Read.All* (Application permission)

**Endpoint**: `https://graph.microsoft.com/v1.0/servicePrincipals`

---

### Microsoft Entra Connect/Cloud Sync

#### Description

This check monitors the time since the last Entra Connect/Cloud Sync synchronisation.

#### Checkmk Service Example

![grafik](https://github.com/user-attachments/assets/4194feb8-abf9-434d-ba53-ea367e9f9c51)

#### Checkmk Parameters

1. **Time since last sync**: Specify the upper levels for the last sync time from Microsoft Entra Connect/Cloud Sync. The default values are 1 hour (WARN) and 3 hours (CRIT). To ignore the last sync time, select "No levels".

#### Microsoft Graph API

**API permissions**: At least *Organization.Read.All* (Application permission)

**Endpoint**: `https://graph.microsoft.com/v1.0/organization/{organizationId}`

---

### Microsoft Entra SAML Certificates

#### Description

This check monitors the expiration time of certificates from Entra enterprise applications with SAML SSO configured.

#### Checkmk Service Example

![grafik](https://github.com/user-attachments/assets/86863d2c-009b-465b-915e-3a1a25922892)

#### Checkmk Parameters

1. **Certificate expiration**: Specify the lower levels for the Microsoft Entra SAML app certificate expiration time. The default values are 14 days (WARN) and 5 days (CRIT). To ignore the certificate expiration, select "No levels".

#### Microsoft Graph API

**API Permissions**: At least *Application.Read.All* (Application permission)

**Endpoint**: `https://graph.microsoft.com/beta/servicePrincipals`

## Steps to Get It Working

To use this Checkmk Special Agent, you must configure a Microsoft Entra application to access the Microsoft Graph API endpoints.
You must also have a host in Checkmk and configure the Special Agent rule for the host.

### Microsoft Entra Configuration
#### Register an Application

1. Sign in to the Microsoft Entra Admin Center (https://entra.microsoft.com) as a Global Administrator (or at least a Privileged Role Administrator)
2. Browse to **Identity** > **Applications** > **App registrations**
3. Select **New registration**
4. Provide a meaningful name (e.g. "Checkmk Special Agent")
5. Select **Accounts in this organizational directory only**
6. Do not specify a **Redirect URI**
7. Click **Register**

> [!NOTE]
> In the overview of your new application registration, you will find the **Application (client) ID** and the **Directory (tenant) ID**.
> You will need this information later for the configuration of the Checkmk Special Agent.

#### Configure the Application
1. Go to **API permissions**
2. Click **Add a permission** > **Microsoft Graph** > **Application permissions**
3. Add all API permissions for all services that you want to monitor (see sections above)
4. Select **Grant admin consent** > **Yes**
5. Go to **Certificates & secrets** and click **New client secret**
6. Enter a description (e.g. the Checkmk Site name) and select an expiration period for the secret

### Checkmk Special Agent Configuration

1. Log in to your Checkmk site

#### Add a New Password

1. Browse to **Setup** > **Passwords**
2. Select **Add password**
3. Specify a **Unique ID** and a **Title**
4. Copy the generated secret from the Microsoft Entra Admin Center to the **Password** field
5. Click **Save**

#### Add Checkmk Host

1. Add a new host in **Setup** > **Hosts**
2. Configure your custom settings and set
    -   **IP address family**: No IP
    -   **Checkmk agent / API integrations**: API integrations if configured, else Checkmk agent
3. Save

#### Add Special Agent Rule

1. Navigate to the Special Agent rule **Setup** > **Microsoft Entra** (use the search bar)
2. Add a new rule and configure the required settings
    -   **Application (client) ID** and **Directory (tenant) ID** from the Microsoft Entra Application
    -   For **Client Secret** select **From password store** and the password from **Add a New Password**
    -   Select all services that you want to monitor
    -   Add the newly created host in **Explicit hosts**
3. Save and go to your new host and discover your new services
4. Activate the changes
