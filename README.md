# Checkmk Plugin: Microsoft Entra Special Agent 

## Plugin Information
The Microsoft Entra Special Agent can be integrated into Checkmk 2.3 or newer.

You can download the .mkp file from releases in this repository to upload it directly to your Checkmk site.

The Plugin provides monitoring of these components:
- Microsoft Entra connect/cloud sync
- Microsoft Entra app registration credentials
- Microsoft Entra SAML certificates

## Prerequisites

This Special Agent uses the Microsoft Graph API to collect the monitoring data.
To access the API, you need a Microsoft Entra Tenant and a Microsoft Entra App Registration with a secret.

You need at least these API **application** permissions for your App Registration:
- *Application.Read.All*
- *Organization.Read.All*

For a more granular option, the required API permissions per check are listed in the next sections.

To implement the check, you need to configure the *Microsoft Entra* Special Agent in Checkmk.
You will need the Microsoft Entra Tenant ID, the Microsoft Entra App Registration ID and Secret.
When you configure the Special Agent, you have the option to select only the services that you want to monitor. You do not have to implement all the checks, but at least one of them.

## Check Details
### Microsoft Entra connect/cloud sync

#### Description

This check monitors the time since the last Entra connect/cloud synchronisation.

#### Checkmk service example

![grafik](https://github.com/user-attachments/assets/4194feb8-abf9-434d-ba53-ea367e9f9c51)

#### Checkmk Parameters

1. **Time since last sync**: Specify the upper levels for the last sync time from Microsoft Entra connect/cloud sync. The default values are 1 hour (WARN) and 3 hours (CRIT). To ignore the last sync time, select 'No levels'.

#### Microsoft Graph API

**API permissions**: At  least *Organization.Read.All* (Application permission)

**Endpoint**: *https://graph.microsoft.com/v1.0/organization/{organizationId}*

### Microsoft Entra app registration credentials

#### Description

This check monitors the expiration time of secrets and certificates from Entra app registrations.

#### Checkmk service example

![grafik](https://github.com/user-attachments/assets/72493199-730c-4dbf-8d4d-d09e8e343ff4)

#### Checkmk Parameters

1. **Credential expiration**: Specify the lower levels for the Microsoft Entra app credential expiration time. The default values are 14 days (WARN) and 5 days (CRIT). To ignore the credential expiration, select 'No levels'.

#### Microsoft Graph API

**API permissions**: At  least *Application.Read.All* (Application permission)

**Endpoint**: *https://graph.microsoft.com/v1.0/applications*

### Microsoft Entra SAML certificates

#### Description

This check monitors the expiration time of certificates from Entra enterprise applications with SAML SSO configured.

#### Checkmk service example

![grafik](https://github.com/user-attachments/assets/86863d2c-009b-465b-915e-3a1a25922892)

#### Checkmk Parameters

1. **Certificate expiration**: Specify the lower levels for the Microsoft Entra SAML app certificate expiration time. The default values are 14 days (WARN) and 5 days (CRIT). To ignore the certificate expiration, select 'No levels'.

#### Microsoft Graph API

**API permissions**: At  least *Application.Read.All* (Application permission)

**Endpoint**: *https://graph.microsoft.com/beta/servicePrincipals*

## Steps to get it working

To use this Checkmk Special Agent, you must configure a Microsoft Entra Application to access the Microsoft Graph API endpoints.
You must also have a host in Checkmk and configure the Special Agent rule for the host.

### Microsoft Entra Configuration
#### Register an Application

1. Sign in to the Microsoft Entra Admin Center (https://entra.microsoft.com) as a Global Administrator (at least a Privileged Role Administrator)
2. Browse to **Identity** > **Applications** > **App registrations**
3. Select **New registration**
4. Provide a meaningful name (e.g. "Checkmk Special Agent")
5. Select **Accounts in this organizational directory only**
6. Do not specify a **Redirect URI**
7. Click **Register**

> [!NOTE]
> In the overview of your new application registration you will find the **Application (client) ID** and the **Directory (tenant) ID**.
> You will need this information later for the configuration of the Checkmk Special Agent.

#### Configure the Application
1. Go to **API permissions**
2. Click **Add a permission** > **Microsoft Graph** > **Application permissions**
3. Add all API permissions for all services that you want to monitor (see sections above)
4. Select **Grant admin consent** > **Yes**
5. Go to **Certificates & secrets** and click on **New client secret**
6. Insert a description (e.g. the Checkmk Site name) and select an expiration period for the secret

### Checkmk Special Agent Configuration

1. Log in to your Checkmk Site
   
#### Add a New Password

1. Browse to **Setup** > **Passwords**
2. Select **Add password**
3. Specify a **Unique ID** and a **Ttile**
4. Copy the generated secret from the Microsoft Entra Admin Center to the **Password** field
5. Click **Save**

#### Add Checkmk Host

1. Add a new host in **Setup** > **Hosts**
2. Configure your custom settings and set
 - **IP address family**: No IP
 - **Checkmk agent / API integrations**: API integrations if configured, else Checkmk agent
3. Save

#### Add Special Agent Rule

1. Navigate to the Special Agent rule **Setup** > **Microsoft Entra** (use the search bar)
2. Add a new rule and configure the required settings
- **Application (client) ID** and **Directory (tenant) ID** from the Microsoft Entra Application
- For **Client secret** select **From password store** and the password from **Add a New Password**
- Select all services that you want to monitor
- Add the newly created host in **Explicit hosts**
3. Save and go to your new host and discover your new services
4. Activate the changes
