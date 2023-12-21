from panos import base, errors, panorama, firewall, policies, objects
import logging
from datetime import datetime, timedelta
from csv import DictWriter
from getpass import getpass


def authenticate(firewall_ip="", username="", password=""):
    """
    This function encapsulates the authentication logic, depends on panos module
    :return: panos object for firewall
    """
    if not firewall_ip:
        firewall_ip = input("Enter firewall IP: ")
    if not username:
        username = input("Username: ")
    if username.lower == 'q':
        exit()
    if not password:
        password = getpass()
    try:
        padevice = base.PanDevice.create_from_device(firewall_ip, username, password)
    except errors.PanURLError as error:
        if '403' in error.message:
            print("Invalid Credential. Please enter a valid username and password or press Q to quit.")
        elif '10060' in error.message:
            print('Unable to connect to firewall. Please enter a valid management IP.')
        else:
            print(error.message)
        padevice = None
        authenticate()
    return padevice


def select_dev_group(pano: panorama.Panorama) -> panorama.DeviceGroup:
    """
    Return a device group from a Panorama object
    :param pano: panorama.Panorama object
    :return: panorama.DeviceGroup object
    """
    device_groups = panorama.DeviceGroup.refreshall(pano)
    if len(device_groups) > 1:
        for idx, dg in enumerate(device_groups):
            print(f'{idx + 1}. {dg}')
        choice = 0
        while choice not in range(1, len(device_groups) + 1):
            if choice:
                print('Please enter a valid number.')
            choice = int(input(f'Please select a device group (enter a number 1-{len(device_groups)}): '))
    else:
        choice = 0
    choice -= 1
    return device_groups[choice]


def get_rulebase(paloaltodevice):
    """
    Pull the rulebase from a panos Firewall or Panormama object.
    :param paloaltodevice: Firewall or Panorama Object
    :return: panos Rulebase object
    """
    if isinstance(paloaltodevice, firewall.Firewall):
        rulebase = policies.Rulebase.refreshall(paloaltodevice, add=True)[0]
        return rulebase
    elif isinstance(paloaltodevice, panorama.Panorama):
        device_group = select_dev_group(paloaltodevice)
        choice = input("Please select a rulebase ('pre' or 'post'): ").lower()
        if choice not in ['pre', 'post']:
            print("Please select a valid rulebase ('pre' or 'post').")
            get_rulebase(paloaltodevice)
        if choice == 'pre':
            rulebase = policies.PreRulebase.refreshall(device_group)[0]
            return rulebase
        elif choice == 'post':
            rulebase = policies.PostRulebase.refreshall(device_group)[0]
            return rulebase
        else:
            print("Please enter a valid rulebase ('pre' or 'post').")
            get_rulebase(paloaltodevice)
    else:
        print('Invalid PANOS Object type.')
        return None


def get_all_rules(pano: panorama.Panorama, device_group: str = "") -> dict:
    """
    Retrieve all rules (security or NAT), either from Panorama or a single Device Group
    :param device_group: Specify a device group to pull rules from
    :param pano: Panorama object
    :return: List of all security or NAT rules in Panorama
    """
    _ = panorama.DeviceGroup.refreshall(pano)
    if device_group and device_group not in [i.name for i in _]:
        raise ValueError(f"Device Group {device_group} not found. Note that device group name is case sensitive.")
    sec_rule_list = panorama.Panorama.findall(pano, class_type=policies.SecurityRule, recursive=True)
    nat_rule_list = panorama.Panorama.findall(pano, class_type=policies.NatRule, recursive=True)
    if device_group:
        sec_rule_list = [i for i in sec_rule_list if i.parent.parent.name == device_group]
        nat_rule_list = [i for i in nat_rule_list if i.parent.parent.name == device_group]

    return {'SEC': sec_rule_list, 'NAT': nat_rule_list}


def add_tag(pano: panorama.Panorama, obj: [policies.SecurityRule, policies.NatRule], tag_value: str):
    """
    Add a tag to a specific Security or NAT rule. This function will create the specified tag if it doesn't exist
    :param pano: Panorama object that contains the rule in question
    :param obj: Rule object to be modified
    :param tag_value: String value for the tag to be applied
    :return: Nothing
    """
    tag = panorama.Panorama.find_or_create(pano, tag_value, objects.Tag)
    try:
        tag.apply()
    except errors.PanXapiError:
        pass
    try:
        if obj.tag and tag_value not in obj.tag:
            obj.tag.append(tag_value)
        elif obj.tag and tag_value in obj.tag:
            pass
        else:
            obj.tag = [tag_value]
        obj.apply()
    except AttributeError:
        raise AttributeError(f"Cannot apply tag to {type(obj)}")


def remove_tag(obj, tag_value):
    if not obj.tag:
        pass
    elif tag_value in obj.tag:
        obj.tag.remove(tag_value)
    obj.apply()


def _parse_hit_data(data, save_to_file=True, output_file="") -> list:
    """
    Takes XML output from Palo Alto "show rule-hit-count" commands and parses it into a CSV
    :param data: XML output from the op command
    :param save_to_file: If True, data will be saved to a CSV file specified in the output_file param
    :param output_file: Path to save data to
    :return: list_out: list of dictionaries with the parsed hit count data
    """
    list_out = list()
    if not data:
        return list_out
    for i in data:
        i_dict = {'name': i.attrib['name']}
        for j in i:
            if 'timestamp' in j.tag:
                ts = int(j.text)
                if ts:
                    val = datetime.fromtimestamp(ts).strftime("%c")
                else:
                    val = ts
            else:
                try:
                    val = int(j.text)
                except ValueError:
                    val = j.text
            i_dict[j.tag] = val
        list_out.append(i_dict)
    if not save_to_file:
        return list_out
    if not output_file:
        print("Output file missing. Files will not be saved.")
        return list_out
    with open(output_file, 'w') as file_out:
        writer = DictWriter(file_out, list_out[0].keys())
        writer.writeheader()
        writer.writerows(list_out)
    return list_out


def _collect_hit_data(fw_obj: [firewall.Firewall, panorama.Panorama], target: str) -> dict:
    """
    Obtain rule hit count data from a Palo Alto device.
    :param fw_obj: Object to run query against
    :param target: Serial number for a target device to collect data from (required for Panorama devices)
    :return: Dictionary with NAT results under key 'NAT' and Security Policy results under key 'SEC'
    E.g. {'NAT': <NAT result xml>, 'SEC': <security policy result xml>}
    """
    count_xpath = "./result/rule-hit-count/vsys/entry/rule-base/entry/rules/"
    nat_op_cmd = "<show><rule-hit-count><vsys><vsys-name><entry name='vsys1'><rule-base><entry name='nat'><rules><all/></rules></entry></rule-base></entry></vsys-name></vsys></rule-hit-count></show>"
    sec_op_cmd = "<show><rule-hit-count><vsys><vsys-name><entry name='vsys1'><rule-base><entry name='security'><rules><all/></rules></entry></rule-base></entry></vsys-name></vsys></rule-hit-count></show>"

    if isinstance(fw_obj, firewall.Firewall):
        nat_counts = fw_obj.op(nat_op_cmd, cmd_xml=False)
        sec_counts = fw_obj.op(sec_op_cmd, cmd_xml=False)
    elif isinstance(fw_obj, panorama.Panorama):
        try:
            int(target)
        except ValueError:
            raise ValueError(f"{target} is an invalid serial number.")
        nat_counts = fw_obj.op(nat_op_cmd, cmd_xml=False, extra_qs=f"target={target}")
        sec_counts = fw_obj.op(sec_op_cmd, cmd_xml=False, extra_qs=f"target={target}")
    else:
        raise SyntaxError("Invalid Palo Alto Object.")
    sec_rule_data = sec_counts.findall(count_xpath)
    parsed_sec_data = _parse_hit_data(sec_rule_data, save_to_file=False)
    nat_rule_data = nat_counts.findall(count_xpath)
    parsed_nat_data = _parse_hit_data(nat_rule_data, save_to_file=False)

    return {'NAT': parsed_nat_data, 'SEC': parsed_sec_data}


def get_all_firewall_hit_data(pano_obj: panorama.Panorama, device_list: list, hit_interval: int = 90):
    hit_data = dict()
    for device in device_list:
        serial_num = device.id
        hostname = device.children[0].hostname
        device_data = _collect_hit_data(pano_obj, target=serial_num)
        nat_usage = _check_usage(device_data['NAT'], usage_interval=hit_interval)
        sec_usage = _check_usage(device_data['SEC'], usage_interval=hit_interval)
        hit_data[hostname] = {'NAT': nat_usage, 'SEC': sec_usage}
        hit_data[hostname]['serial'] = serial_num
    return hit_data


def _check_usage(rule_data: list, usage_interval: int = 90):
    fmt_string = "%a %b %d %H:%M:%S %Y"
    used_rules = list()
    unused_rules = list()

    for rule in rule_data:
        time_since_creation = datetime.now() - datetime.strptime(rule['rule-creation-timestamp'], fmt_string)
        if rule['last-hit-timestamp'] == 0:
            last_hit = datetime.fromtimestamp(0)
        else:
            last_hit = datetime.strptime(rule['last-hit-timestamp'], fmt_string)
        if rule['first-hit-timestamp'] == 0 and time_since_creation > timedelta(days=usage_interval):
            unused_rules.append(rule['name'])
            continue
        if datetime.now() - last_hit > timedelta(days=usage_interval):
            unused_rules.append(rule['name'])
        else:
            used_rules.append(rule['name'])

    return {"used": used_rules, "unused": unused_rules}


def is_rule_used(rule_obj: [policies.SecurityRule, policies.NatRule], usage_info: dict):
    rule_name = rule_obj.name
    used = False
    if isinstance(rule_obj, policies.NatRule):
        rule_type = 'NAT'
    elif isinstance(rule_obj, policies.SecurityRule):
        rule_type = 'SEC'
    else:
        raise ValueError(f'{rule_obj.name} is not a Security or NAT rule.')
    for fw in usage_info:
        used = rule_name in usage_info[fw][rule_type]['used']
    return used


def valid_delete(rule_obj: [policies.SecurityRule, policies.NatRule], script_tag: str, exclude_tag: str,
                 interval: int) -> bool:
    """
    This function checks to see if a given rule is safe to delete. It uses the following criteria:
    1. Rule is disabled
    2. Rule contains a tag applied by the policy-optimizer.py script
    :param rule_obj: Rule to be examined for deletion
    :param script_tag: Tag to be examined to determine candidacy for deletion
    :param exclude_tag: If this tag is present on the rule, it will not be eligible for deletion
    :param interval: How long ago the rule needs to have been disabled to be eligible for deletion
    :return: True if the rule should be deleted and False if not
    """
    if not rule_obj.disabled:
        return False
    if not rule_obj.tag:
        return False
    if exclude_tag in rule_obj.tag:
        return False
    tag_check = [i for i in rule_obj.tag if script_tag in i and i != 'SCRIPT-UNUSED'].sort()
    if not tag_check:
        return False
    date_today = datetime.today()
    # noinspection PyUnresolvedReferences
    disable_date = datetime.strptime(tag_check[-1].split()[-1], "%y-%m-%d")
    date_delta = date_today - disable_date
    if date_delta > timedelta(days=interval):
        return True
    else:
        return False


def palo_logger(name: str, log_file_path: str, format_str: str, level=logging.INFO):
    """
    Create a logger instance to allow for logging to as many log files as needed.
    :param name: Name of the logger
    :param log_file_path: Path to save the log file to
    :param format_str: Format for the log entry header
    :param level: Set the level for the logger. INFO by deafult
    :return: logger instance
    """

    handler = logging.FileHandler(log_file_path)
    formatter = logging.Formatter(format_str)
    handler.setFormatter(formatter)
    logger = logging.getLogger(name)
    logger.setLevel(level)
    logger.addHandler(handler)
    return logger


def check_for_tag(obj: [policies.SecurityRule, policies.NatRule], tag_value: str) -> bool:
    """
    This function checks a Security or NAT rule object for a particular tag
    :param obj: Rule object to check
    :param tag_value: Tag value to check for
    :return: Boolean result of tag check
    """
    if not obj.tag:
        return False
    elif tag_value in obj.tag:
        return True
    else:
        return False


def _build_dg_hierarchy(panorama: panorama.Panorama):
    # dg_hierarchy = panorama.op('show dg-hierarchy')
    resp = panorama.op("show dg-hierarchy")
    data = resp.find("./result/dg-hierarchy")

    ans = {}
    nodes = [(None, x) for x in data.findall("./dg")]
    for parent, elm in iter(nodes):
        ans[elm.attrib["name"]] = parent
        nodes.extend((elm.attrib["name"], x) for x in elm.findall("./dg"))
    ans_out = dict()
    for child, parent in ans.items():
        if parent not in ans_out.keys():
            ans_out[parent] = [child]
        else:
            ans_out[parent].append(child)

    return ans_out


def find_children_dgs(parent: str, hierarchy: dict):
    # Found parent with children
    child_out = set()
    try:
        children = hierarchy[parent]
        child_out.update(set(children))
        for child in children:
            g_children = find_children_dgs(child, hierarchy)
            child_out.update(g_children)
        return child_out
    # If dg not found as a parent, return children
    except KeyError:
        return child_out


def build_member_devices(panorama_obj: panorama.Panorama):
    device_hierarchy = _build_dg_hierarchy(panorama_obj)
    devices = panorama_obj.refresh_devices(include_device_groups=False, only_connected=False)
    dgs = panorama.DeviceGroup.refreshall(panorama_obj)
    device_membership = dict()
    dg_membership = dict()
    for dg in dgs:
        dg_membership[dg.name] = find_children_dgs(dg.name, device_hierarchy)
    for dg, children in dg_membership.items():
        parent_dg_obj = panorama.DeviceGroup.find(panorama_obj, dg)
        device_membership[dg] = [i for i in parent_dg_obj.children if isinstance(i, firewall.Firewall)]
        for child in children:
            dg_obj = panorama.DeviceGroup.find(panorama_obj, child)
            devices = [i for i in dg_obj.children if isinstance(i, firewall.Firewall)]
            device_membership[dg].extend(devices)
    return device_membership

