# Unofficial Smart-ID Keycloak SPI
This Keycloak provider allows you to authenticate Keycloak users via Smart-ID.

## Prerequisites
To use this SPI, you will need to have a direct Smart-ID contract with SK ID Solutions, the developer of Smart-ID. As of writing this, this service starts at 55€/month and is available at https://www.skidsolutions.eu/en/services/smart-id/?service/validity_confirmation.

The IP address of the Keycloak server as well as the service display name you wish to use need to be whitelisted by SK.

## Configuration
Upon installation of the SPI, create an authentication flow that contains one required Generic sub-flow, which contains the following steps:

- A "Username Form" step
- A "Smart-ID" step, in whose config you must set the Relying Parts UIID (RPUUID in the SK portal) and the Relying Party Service Name (which must be one of the approved names listed under "Service Names" in the SK portal)

## User Mapping
This SPI uses a custom user attribute, "smartid_semantics_identifier", to store the semantics identifier, which consists of the country code and personal ID number. For example, a person with the Estonian personal ID code 12345678910 would have the semantics identifier "PNOEE-12345678910".