from os import getenv
from ansible_vault import Vault
from PaloAPIUtils import *

VAULT_FILE = "vault.yml"
SCRIPT_HEADER = 'SCRIPT-UNUSED'  # Header for the tag applied by the script
DEVICE_GROUP = 'PA-VM'  # Case sensitive
EXCLUSION_TAG = ""  # Case sensitive
DISABLE_INTERVAL = 90  # Number of days a rule is unused before it is disabled by the script
DELETE_INTERVAL = 30  # Number of days a rule has been disabled before it is deleted by the script.
REPORT_MODE = False  # Run the script without making changes to the firewall or Panorama. Only creates logs
CLEAN_MODE = False  # Removes all tags added by the script and re-enables all rules disabled by the script

DATE_STAMP = datetime.today().strftime("%y-%m-%d")
SCRIPT_TAG = f'{SCRIPT_HEADER} {DATE_STAMP}'
CLEAN_MODE_LOGGER = palo_logger("clean_up_logger",
                                f"Logs/clean-mode-{DATE_STAMP}.log",
                                '%(asctime)s %(levelname)s %(message)s')
REPORT_MODE_LOGGER = palo_logger("report_only_logger",
                                 f"Logs/report-mode-{DATE_STAMP}.log",
                                 '%(asctime)s %(levelname)s %(message)s')
ACTIVE_MODE_LOGGER = palo_logger("clean_up_logger",
                                 f"Logs/policy-optimizer-{DATE_STAMP}.log",
                                 '%(asctime)s %(levelname)s %(message)s')


# TODO Discuss authentication


def main(report_mode=False, clean_mode=False, single_dg=""):
    """
    This is the main policy optimization function. Calling this function will run the policy optimizer tool. It can
    be run in 3 modes:
    1. Clean mode - This will rarely be used, but can be used to revert changes made by this script. It will find all
    rules that have tags generated by this script and re-enable them, as well as remove the tags.
    2. Report mode - Generate a log file to show what *would* have happened without making changes to the firewall. Useful
    for estimating impact at any given time
    3. Active mode (default) - This is the main mode that will perform optimizations and make changes to the firewall.
    :param report_mode: Run the script in Report mode. Cannot be run with Clean mode enabled.
    :param clean_mode: Run the script in Clean mode. Cannot be run with Report mode enabled.
    :param single_dg: Specify a single device group to run the optimizer on. Only rules in the specified device group
    will be tagged, disabled, or deleted.
    :return:
    """
    # Authenticate to Panorama and collect all rules
    vault = Vault(getenv("VAULT_KEY"))
    vault_data = vault.load(open(VAULT_FILE).read())
    panorama_obj = authenticate(getenv("HOST"), vault_data['palo-user'], vault_data['palo-pass'])
    del vault, vault_data
    all_rules = get_all_rules(panorama_obj, single_dg)

    # Run the script in Clean mode
    if clean_mode and not report_mode:
        all_rule_list = all_rules['SEC'] + all_rules['NAT']
        for rule in all_rule_list:
            if not rule.tag:
                continue
            for tag in rule.tag:
                if SCRIPT_HEADER in tag:
                    remove_tag(rule, tag)
                    CLEAN_MODE_LOGGER.info(f"CLEAN MODE: {tag} removed from {type(rule)} {rule.name}.")
                if rule.disabled and SCRIPT_TAG in rule.tag:
                    rule.disabled = False
                    rule.apply()
                    CLEAN_MODE_LOGGER.info(f"CLEAN MODE: {rule} has been enabled.")
        exit(0)
    elif clean_mode and report_mode:
        logging.error("Cannot clean system while in report mode.")
        exit(0)

    # Get connected devices and hit data. If a firewall is not connected to Panorama, it will not be affected by this
    # script.
    devices = panorama_obj.refresh_devices(include_device_groups=False, only_connected=True)
    all_hit_data = get_all_firewall_hit_data(panorama_obj, devices, DISABLE_INTERVAL)

    all_used_rules = {'SEC': list(), 'NAT': list()}
    all_unused_rules = {'SEC': list(), 'NAT': list()}
    for fw_device in all_hit_data:
        all_used_rules['SEC'].extend(all_hit_data[fw_device]['SEC']['used'])
        all_used_rules['NAT'].extend(all_hit_data[fw_device]['NAT']['used'])
        all_unused_rules['SEC'].extend(all_hit_data[fw_device]['SEC']['unused'])
        all_unused_rules['NAT'].extend(all_hit_data[fw_device]['NAT']['unused'])

    # Tag unused Security rules
    for rule in all_unused_rules['SEC']:
        if EXCLUSION_TAG:
            obj_list = [obj for obj in all_rules['SEC'] if obj.uid == rule and EXCLUSION_TAG not in obj.tag]
        else:
            obj_list = [obj for obj in all_rules['SEC'] if obj.uid == rule]
        if len(obj_list) == 1 and not report_mode:
            add_tag(panorama_obj, obj_list[0], SCRIPT_TAG)
            ACTIVE_MODE_LOGGER.info(f"Tag {SCRIPT_TAG} added to {obj_list[0]}")
        elif len(obj_list) == 1 and report_mode:
            REPORT_MODE_LOGGER.info(f"Tag {SCRIPT_TAG} added to {obj_list[0]}")
        elif len(obj_list) > 1 and not report_mode:
            [add_tag(panorama_obj, i, SCRIPT_TAG) for i in obj_list if not is_rule_used(i, all_hit_data)]
            [ACTIVE_MODE_LOGGER.info(f"Tag {SCRIPT_TAG} added to {i}") for i in obj_list if
             not is_rule_used(i, all_hit_data)]
        elif len(obj_list) > 1 and report_mode:
            [REPORT_MODE_LOGGER.info(f"Tag {SCRIPT_TAG} added to {i}") for i in obj_list if
             not is_rule_used(i, all_hit_data)]
        elif rule in ['intrazone-default', 'interzone-default']:
            pass
        else:
            if not report_mode:
                ACTIVE_MODE_LOGGER.error(f"No rule named {rule} found in Panorama")
            else:
                REPORT_MODE_LOGGER.error(f"No rule named {rule} found in Panorama")

    # Tag unused NAT rules
    for rule in all_unused_rules['NAT']:
        if EXCLUSION_TAG:
            obj_list = [obj for obj in all_rules['NAT'] if obj.uid == rule and EXCLUSION_TAG not in obj.tag]
        else:
            obj_list = [obj for obj in all_rules['NAT'] if obj.uid == rule]
        if len(obj_list) == 1 and not report_mode:
            add_tag(panorama_obj, obj_list[0], SCRIPT_TAG)
            ACTIVE_MODE_LOGGER.info(f"Tag {SCRIPT_TAG} added to {obj_list[0]}")
        elif len(obj_list) == 1 and report_mode:
            REPORT_MODE_LOGGER.info(f"Tag {SCRIPT_TAG} added to {obj_list[0]}")
        elif len(obj_list) > 1 and not report_mode:
            [add_tag(panorama_obj, i, SCRIPT_TAG) for i in obj_list if not is_rule_used(i, all_hit_data)]
            [ACTIVE_MODE_LOGGER.info(f"Tag {SCRIPT_TAG} added to {i}") for i in obj_list if
             not is_rule_used(i, all_hit_data)]
        elif len(obj_list) > 1 and report_mode:
            [REPORT_MODE_LOGGER.info(f"Tag {SCRIPT_TAG} added to {i}") for i in obj_list if
             not is_rule_used(i, all_hit_data)]
        else:
            if not report_mode:
                ACTIVE_MODE_LOGGER.error(f'No rule named {rule} found in Panorama.')
            else:
                REPORT_MODE_LOGGER.error(f'No rule named {rule} found in Panorama.')

    # Remove tag from used Security rules
    for rule in all_used_rules['SEC']:
        obj_list = [obj for obj in all_rules['SEC'] if obj.uid == rule]
        if len(obj_list) == 1:
            remove_tag(obj_list[0], SCRIPT_TAG)
        elif len(obj_list) > 1:
            [remove_tag(i, SCRIPT_TAG) for i in obj_list if is_rule_used(i, all_hit_data)]
        elif rule in ['intrazone-default', 'interzone-default']:
            pass
        else:
            if not report_mode:
                ACTIVE_MODE_LOGGER.error(f"No rule named {rule} found in Panorama")
            elif report_mode:
                REPORT_MODE_LOGGER.error(f"No rule named {rule} found in Panorama")

    # Remove tag from used NAT rules
    for rule in all_used_rules['NAT']:
        obj_list = [obj for obj in all_rules['NAT'] if obj.uid == rule]
        if len(obj_list) == 1 and not report_mode:
            remove_tag(obj_list[0], SCRIPT_TAG)
            ACTIVE_MODE_LOGGER.info(f"Tag {SCRIPT_TAG} removed from {obj_list[0]}")
        elif len(obj_list) == 1 and report_mode:
            REPORT_MODE_LOGGER.info(f"Tag {SCRIPT_TAG} removed from {obj_list[0]}")
        elif len(obj_list) > 1 and not report_mode:
            [remove_tag(i, SCRIPT_TAG) for i in obj_list if is_rule_used(i, all_hit_data)]
            [ACTIVE_MODE_LOGGER.info(f"Tag {SCRIPT_TAG} removed from {i}") for i in obj_list if
             is_rule_used(i, all_hit_data)]
        elif len(obj_list) > 1 and report_mode:
            [REPORT_MODE_LOGGER.info(f"Tag {SCRIPT_TAG} removed from {i}") for i in obj_list if
             is_rule_used(i, all_hit_data)]
        else:
            if not report_mode:
                ACTIVE_MODE_LOGGER.error(f"No rule named {rule} found in Panorama")
            elif report_mode:
                REPORT_MODE_LOGGER.error(f"No rule named {rule} found in Panorama")

    # Disable tagged rules
    for rule in all_rules['SEC']:
        if rule.tag and SCRIPT_TAG in rule.tag:
            if not report_mode:
                rule.disabled = True
                rule.apply()
                ACTIVE_MODE_LOGGER.warning(f"{rule.name} disabled.")
            elif report_mode:
                REPORT_MODE_LOGGER.warning(f"{rule.name} disabled.")
        if valid_delete(rule, SCRIPT_HEADER, EXCLUSION_TAG, DELETE_INTERVAL):
            if not report_mode:
                rule.delete()
                ACTIVE_MODE_LOGGER.warning(f'Rule {rule.name} deleted')
            else:
                REPORT_MODE_LOGGER.warning(f"Rule {rule.name} deleted.")
    for rule in all_rules['NAT']:
        if rule.tag and SCRIPT_TAG in rule.tag:
            if not report_mode:
                rule.disabled = True
                rule.apply()
                ACTIVE_MODE_LOGGER.warning(f"Rule {rule.name} disabled.")
            else:
                REPORT_MODE_LOGGER.warning(f"Rule {rule.name} disabled.")
            if valid_delete(rule, SCRIPT_HEADER, EXCLUSION_TAG, DELETE_INTERVAL):
                if not report_mode:
                    rule.delete()
                    ACTIVE_MODE_LOGGER.warning(f'Rule {rule.name} deleted')
                else:
                    REPORT_MODE_LOGGER.warning(f"Rule {rule.name} deleted.")
    if not report_mode:
        ACTIVE_MODE_LOGGER.info("Policy optimization complete.")
    else:
        REPORT_MODE_LOGGER.info("Report of policy optimization complete.")
    # If desired, enable the following line to automatically commit configuration to Panorama. This will NOT push configuration
    # to the firewall:
    # panorama_obj.commit()


if __name__ == '__main__':
    main(report_mode=REPORT_MODE, clean_mode=CLEAN_MODE, single_dg=DEVICE_GROUP)
