# Mosyle to Snipe-IT Sync

This Python script synchronizes device information between Mosyle MDM and Snipe-IT asset management system. It pulls device data from Mosyle and either updates existing assets or creates new ones in Snipe-IT.

## Features

- JWT token generation for Mosyle API authentication (required as of February 2024)
- Retrieves device information from Mosyle MDM with pagination support
- Creates or updates assets in Snipe-IT
- Creates models in Snipe-IT if they don't exist
- Maps Mosyle device attributes to Snipe-IT custom fields
- Handles device-to-user assignments
- Sets purchase dates based on Mosyle first enrollment dates
- Advanced rate limiting with exponential backoff
- Dry run mode for testing

## Requirements

- Python 3.6 or higher
- `requests` module

## Installation

1. Clone this repository or download the script files
2. Install required Python modules:

```bash
pip install requests
```

3. Copy `example.settings.json` to `settings.json` and update it with your specific information:

```bash
cp example.settings.json settings.json
```

4. Edit `settings.json` to include your Mosyle and Snipe-IT credentials and configuration details

## Configuration

The script requires a configuration file (`settings.json`) with the following sections:

### JSON Configuration Format

```json
{
  "mosyle": {
    "api_url": "https://businessapi.mosyle.com/v2",
    "email": "your_mosyle_admin_email@example.com",
    "password": "your_mosyle_password",
    "access_token": "YOUR_MOSYLE_ACCESS_TOKEN",
    "jwt_token": ""
  },
  "snipeit": {
    "api_url": "https://your-snipeit-instance.com",
    "api_key": "YOUR_SNIPEIT_API_KEY",
    "default_status": 1,
    "manufacturer_id": 1,
    "macos_category_id": 1,
    "ios_category_id": 2,
    "tvos_category_id": 3,
    "macos_fieldset_id": 1,
    "ios_fieldset_id": 2,
    "tvos_fieldset_id": 3,
    "rate_limit": 120
  },
  "log_directory": "/path/to/logs"
}
```

### Mosyle Configuration

- `api_url`: Mosyle API URL
- `email`: Your Mosyle administrator email (required for JWT token generation)
- `password`: Your Mosyle administrator password (required for JWT token generation)
- `access_token`: Mosyle API access token
- `jwt_token`: Mosyle JWT token (will be generated and stored automatically)

### Snipe-IT Configuration

- `api_url`: Snipe-IT API URL
- `api_key`: Snipe-IT API key
- `default_status`: Default status ID for new assets (e.g., 1 for "Ready to Deploy")
- `manufacturer_id`: Manufacturer ID for Apple in your Snipe-IT instance
- `macos_category_id`, `ios_category_id`, `tvos_category_id`: Category IDs for different device types
- `macos_fieldset_id`, `ios_fieldset_id`, `tvos_fieldset_id`: (Optional) Custom fieldset IDs for different device types
- `rate_limit`: API rate limit (default: 120 requests per minute)

### General Configuration

- `log_directory`: Directory where log files will be stored (default: current directory)

## Obtaining Required IDs

Before using the script, you'll need to obtain several IDs from your Snipe-IT instance:

1. **Manufacturer ID**: Navigate to "Manufacturers" in Snipe-IT, find Apple, and note the ID from the URL (e.g., `/manufacturers/1`)
2. **Category IDs**: Navigate to "Categories" in Snipe-IT, find your categories for different device types, and note the IDs from the URLs
3. **Status IDs**: Navigate to "Statuslabels" in Snipe-IT and note the IDs for the statuses you want to use
4. **Fieldset IDs**: If you're using custom fields, navigate to "Custom Fields" in Snipe-IT and note the fieldset IDs

## Custom Fields

For the script to map Mosyle device attributes to Snipe-IT custom fields, you need to create the following custom fields in Snipe-IT:

- `snipeit_os_version`: OS version
- `snipeit_imei`: IMEI number for cellular devices
- `snipeit_mac_address`: WiFi MAC address
- `snipeit_model_name`: Model name
- `snipeit_last_checkin`: Last check-in date
- `snipeit_battery_level`: Battery level
- `snipeit_available_space`: Available disk space
- `snipeit_total_disk`: Total disk space
- `snipeit_supervised`: Device supervision status
- `snipeit_ethernet_mac`: Ethernet MAC address
- `snipeit_bluetooth_mac`: Bluetooth MAC address
- `snipeit_activation_lock`: Activation lock status
- `snipeit_first_enrollment`: First enrollment date

You can add or remove field mappings by modifying the `field_mappings` dictionary in the `build_asset_payload` method.

## JWT Token Management

The script will automatically handle JWT token management:

1. It will first try to use the token stored in settings.json
2. If the API rejects the token or no token exists, it will automatically generate a new token using the credentials in settings.json
3. The new token will be saved back to settings.json for future use

You can also manually generate a token:

```bash
python mosyle_to_snipe.py token
```

## Usage

Run the script with the following command:

```bash
python mosyle_to_snipe.py [options]
```

### Options

- `--config`: Path to configuration file (default: `settings.json`)
- `--device-type`: Type of devices to sync (`all`, `ios`, `mac`, or `tvos`, default: `all`)
- `--dry-run`: Dry run mode (no changes will be made to Snipe-IT)

### Examples

Sync all devices:
```bash
python mosyle_to_snipe.py
```

Sync only Mac devices:
```bash
python mosyle_to_snipe.py --device-type mac
```

Test the script without making changes:
```bash
python mosyle_to_snipe.py --dry-run
```

Use a different configuration file:
```bash
python mosyle_to_snipe.py --config custom_settings.json
```

## Logging

The script logs information to both the console and a log file (`mosyle_snipeit_sync.log`). By default, the log file is created in the current directory, but you can specify a different location using the `log_directory` setting in your `settings.json` file.

The log includes details about devices processed, assets created or updated, and any errors encountered. If the specified log directory doesn't exist, the script will attempt to create it. If it cannot write to the specified directory, it will fall back to using the current directory.

## Special Features

### Mosyle as Source of Truth
The script uses Mosyle as the source of truth for several key asset attributes:

1. **Device Models**: If a device has a different model in Snipe-IT compared to Mosyle, the script will update the Snipe-IT model to match what's in Mosyle.

2. **Asset Tags**: If an asset tag in Snipe-IT differs from the one in Mosyle, the script will update Snipe-IT to use the asset tag from Mosyle.

### Purchase Dates
The script automatically sets purchase dates in Snipe-IT based on the "first enroll date" from Mosyle. The purchase date is set to the first day of the month of the enrollment date.

For example:
- First enrollment date in Mosyle: "07:14 PM - 08/05/2024"
- Purchase date set in Snipe-IT: "2024-08-01"

If an asset already has a purchase date set in Snipe-IT, the script will respect that date and not overwrite it with the Mosyle enrollment date.

## Automation

You can set up a cron job or scheduled task to run the script automatically at regular intervals.

### Example cron job (daily at 2 AM):

```bash
0 2 * * * /path/to/python /path/to/mosyle_to_snipe.py >> /path/to/additional_logs.log 2>&1
```

## Troubleshooting

### Rate Limiting

If you encounter rate limiting issues with the Snipe-IT API, you can adjust the `rate_limit` setting in the configuration file. The default is 120 requests per minute, which is the standard Snipe-IT API rate limit.

### Authentication Errors

- For Mosyle, the script will automatically refresh JWT tokens when needed
- For Snipe-IT, make sure your API key has sufficient permissions

### Missing Devices

- Check that devices in Mosyle have serial numbers
- Verify that user-enrolled devices are not being filtered out if you want to include them

### Logging Issues

- If you encounter permissions issues with log files, check that the user running the script has write access to the specified `log_directory`
- If running as a scheduled task or cron job, ensure that the service account has the necessary permissions