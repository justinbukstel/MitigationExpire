# MitigationExpire

MitigationExpire is a utility designed to expire mitigations in Veracode for both Static and SCA. This tool specifically targets policy-level mitigations for Static and SCA vulnerability mitigations, excluding license mitigations. The expiration timeline is set at findings that have been mitigated for more than 30 days (default). If you want to change the days, you can edit the days_threshold variable in the script

## Requirements

**1. Veracode Credentials File Local:**

Ensure you have your Veracode credentials file locally available for the utility to authenticate with the Veracode API.

## Usage

1. **Clone the Repository:**
   ```bash
   git clone https://github.com/your-username/MitigationExpire.git
   ```

2. **Navigate to the Project Directory:**
   ```bash
   cd MitigationExpire
   ```

3. **Install Dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

4. **Configure Veracode Credentials:**
   Place your Veracode credentials file locally in the project directory.

5. **Run the Utility:**
   ```bash
   python mitigation_expire.py
   ```

## Notes

- The utility will only expire mitigations older than 30 days.
- License mitigations are not affected; only policy-level mitigations and SCA vulnerability mitigations are considered.
- Ensure your Veracode credentials file is correctly configured for authentication.

Feel free to contribute or report issues on [GitHub](https://github.com/your-username/MitigationExpire).

