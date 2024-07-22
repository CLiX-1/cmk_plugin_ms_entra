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

## Microsoft Entra connect/cloud sync

### Description

This check monitors the time since the last Entra connect/cloud synchronisation.

### Checkmk service example

![grafik](https://github.com/user-attachments/assets/4194feb8-abf9-434d-ba53-ea367e9f9c51)

### Checkmk Parameters

1. **Time since last sync**: Specify the upper levels for the last sync time from Microsoft Entra connect/cloud sync. The default values are 1 hour (WARN) and 3 hours (CRIT). To ignore the last sync time, select 'No levels'.

### Microsoft Graph API

**API permissions**: At  least *Organization.Read.All* (Application permission)

**Endpoint**: *https://graph.microsoft.com/v1.0/organization/{organizationId}*

## Microsoft Entra app registration credentials

### Description

This check monitors the expiration time of secrets and certificates from Entra app registrations.

### Checkmk service example

![grafik](https://github.com/user-attachments/assets/72493199-730c-4dbf-8d4d-d09e8e343ff4)

### Checkmk Parameters

1. **Credential expiration**: Specify the lower levels for the Microsoft Entra app credential expiration time. The default values are 14 days (WARN) and 5 days (CRIT). To ignore the credential expiration, select 'No levels'.

### Microsoft Graph API

**API permissions**: At  least *Application.Read.All* (Application permission)

**Endpoint**: *https://graph.microsoft.com/v1.0/applications*

## Microsoft Entra SAML certificates

### Description

This check monitors the expiration time of certificates from Entra enterprise applications with SAML SSO configured.

### Checkmk service example

![grafik](https://github.com/user-attachments/assets/86863d2c-009b-465b-915e-3a1a25922892)

### Checkmk Parameters

1. **Certificate expiration**: Specify the lower levels for the Microsoft Entra SAML app certificate expiration time. The default values are 14 days (WARN) and 5 days (CRIT). To ignore the certificate expiration, select 'No levels'.

### Microsoft Graph API

**API permissions**: At  least *Application.Read.All* (Application permission)

**Endpoint**: *https://graph.microsoft.com/beta/servicePrincipals*
