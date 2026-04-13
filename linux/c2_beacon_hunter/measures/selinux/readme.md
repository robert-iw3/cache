### How to Use

1. Save both scripts in the same directory as your policy files.
2. Make them executable:

```bash
chmod +x remove_c2_restrict.sh toggle_c2_restrict.sh
```

3. Usage examples:

```bash
# Enable restricted mode
sudo ./toggle_c2_restrict.sh on

# Disable restricted mode
sudo ./toggle_c2_restrict.sh off

# Check status
sudo ./toggle_c2_restrict.sh status

# Completely remove the policy
sudo ./remove_c2_restrict.sh
```