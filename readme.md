# Mosyle to Snipe-IT Sync Script

This Python script synchronizes device information between Mosyle MDM and Snipe-IT asset management system. It pulls device data from Mosyle and either updates existing assets or creates new ones in Snipe-IT.

## Features

- **Full MDM Integration**: Pulls complete device information from Mosyle Mobile Device Management
- **Smart Asset Syncing**: Creates new assets or updates existing ones based on serial number matching
- **Conflict Resolution**: Intelligently handles serial number conflicts and casing differences
- **Rate Limit Management**: Implements advanced rate limiting with exponential backoff
- **Batch Processing**: Processes devices in configurable batches to reduce API load
- **Pagination Support**: Handles large device inventories through automatic pagination
- **Comprehensive Logging**: Detailed logging for troubleshooting and auditing

## Requirements

- Python 3.6+
- `requests` module
- JSON configuration file

## Installation

1. Clone or download this script to your server or local machine
2. Install required Python modules:
   ```
   pip install requests
   ```
3. Create a `settings.json` file (see Configuration section)
4. Run the script:
   ```
   python mosyle_snipeit_sync.py
   ```

## Configuration

Create a `settings.json` file in the same directory as the script with the following structure:

```json
{
  "mosyle": {
    "api_url": "https://managerapi.mosyle.com/v2",
    "email": "your-admin-email@example.com",
    "password": "your-admin-password",
    "access_token": "your-mosyle-access-token",
    "jwt_token": ""
  },
  "snipeit": {
    "api_url": "https://your-snipeit-instance.example.com",
    "api_key": "your-snipeit-api-key",
    "default_status": "2",
    "manufacturer_id": "1",
    "macos_category_id": "3",
    "ios_category_id": "4",
    "tvos_category_id": "5",
    "macos_fieldset_id": "1", 
    "ios_fieldset_id": "2",
    "tvos_fieldset_id": "3",
    "rate_limit": 60
  }
}
```

### Mosyle Configuration

- `api_url`: The base URL for the Mosyle API (usually `https://managerapi.mosyle.com/v2`)
- `email`: Your Mosyle administrator email
- `password`: Your Mosyle administrator password
- `access_token`: Your Mosyle API access token
- `jwt_token`: Leave empty on first run; the script will obtain and save it

### Snipe-IT Configuration

- `api_url`: Your Snipe-IT instance URL
- `api_key`: Your Snipe-IT API key
- `default_status`: ID for default asset status (e.g., 2 = "Ready to Deploy")
- `manufacturer_id`: ID for Apple in your Snipe-IT instance
- Category IDs: Different categories for different device types
  - `macos_category_id`: Category ID for Mac computers
  - `ios_category_id`: Category ID for iOS devices
  - `tvos_category_id`: Category ID for Apple TVs
- Fieldset IDs: Custom fieldsets for each device type
  - `macos_fieldset_id`: Fieldset ID for Mac-specific fields
  - `ios_fieldset_id`: Fieldset ID for iOS-specific fields
  - `tvos_fieldset_id`: Fieldset ID for tvOS-specific fields
- `rate_limit`: Maximum API calls per minute (default is 60)

## Finding IDs in Snipe-IT

To find the various IDs needed for configuration:

### Status IDs

1. Go to Admin → Status Labels
2. The ID is in the URL when editing a status (e.g., `/statuslabels/2/edit` means ID is `2`)

### Manufacturer ID

1. Go to Admin → Manufacturers
2. The ID is in the URL when editing a manufacturer (e.g., `/manufacturers/1/edit` means ID is `1`)

### Category IDs

1. Go to Admin → Categories
2. The ID is in the URL when editing a category (e.g., `/categories/3/edit` means ID is `3`)

### Fieldset IDs

1. Go to Admin → Custom Fields → Fieldsets
2. The ID is in the URL when editing a fieldset (e.g., `/fields/fieldsets/1/edit` means ID is `1`)

## Command-Line Options

```
python mosyle_snipeit_sync.py [options]

Options:
  --config CONFIG_FILE     Path to configuration file (default: settings.json)
  --device-type {all,ios,mac,tvos}
                           Type of devices to sync (default: all)
  --dry-run                Dry run (do not make changes to Snipe-IT)
  --batch-size BATCH_SIZE  Number of devices to process in each batch (default: 50)
  --batch-delay BATCH_DELAY
                           Delay in seconds between batches (default: 5.0)
```

### Examples

Sync all device types with default settings:
```
python mosyle_snipeit_sync.py
```

Sync only Mac devices:
```
python mosyle_snipeit_sync.py --device-type mac
```

Dry run (no changes to Snipe-IT):
```
python mosyle_snipeit_sync.py --dry-run
```

Process in smaller batches with longer delays (for stricter rate limits):
```
python mosyle_snipeit_sync.py --batch-size 25 --batch-delay 10
```

## Field Mapping

The script maps the following fields from Mosyle to Snipe-IT:

| Snipe-IT Field | Mosyle Field |
|----------------|--------------|
| Serial Number | serial_number |
| Asset Tag | asset_tag or serial_number |
| Device Name | device_name |
| Model | device_model |
| OS Version | osversion |
| IMEI | imei |
| MAC Address | wifi_mac_address |
| Model Name | model_name |
| Last Check-in | date_last_beat |
| Battery Level | battery |
| Available Space | available_disk |
| Total Disk | total_disk |
| Supervised | is_supervised |
| Ethernet MAC | ethernet_mac_address |
| Bluetooth MAC | bluetooth_mac_address |
| Activation Lock | isActivationLockEnabled |
| First Enrollment | date_first_enrollment |

## Troubleshooting

### Common Issues

#### 405 INVALID_METHOD Error
This occurs when the Mosyle API endpoint is called with the wrong HTTP method. The script uses POST for all Mosyle API calls.

#### 429 Too Many Requests
This happens when you've hit the Snipe-IT API rate limit. The script implements automatic rate limiting and exponential backoff, but you may need to:
- Increase the `--batch-delay` value
- Decrease the `--batch-size` value
- Adjust the `rate_limit` in your settings.json

#### Serial Number Conflicts
The script automatically handles serial number conflicts by:
1. Never updating serial numbers for existing assets
2. Searching for assets with case-insensitive matching
3. Attempting to update instead of create when conflicts occur

#### JWT Token Issues
If you encounter authentication problems, try:
1. Delete the `jwt_token` value in settings.json
2. Verify your Mosyle email, password, and access token
3. Run the script again to obtain a new JWT token

## Logging

The script creates a log file `mosyle_snipeit_sync.log` in the same directory. This log contains detailed information about the sync process, including:

- API requests and responses
- Device processing details
- Errors and warnings
- Statistics about created/updated/skipped assets

Check this log for troubleshooting or to verify the sync results.

## License

This script is provided as-is without any warranty. Use at your own risk.

## Acknowledgments

This script was created to help IT admins manage their Apple device inventory more efficiently by keeping Mosyle MDM and Snipe-IT asset management in sync.