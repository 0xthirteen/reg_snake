

import socket
import logging
import sys
import argparse
from impacket.examples import logger
from impacket.examples.utils import parse_target
from impacket.dcerpc.v5.dcom import wmi
from impacket.dcerpc.v5.dtypes import NULL
from impacket.dcerpc.v5.dcomrt import DCOMConnection, NULL



class WMI:
    def __init__(self, target, namespace, username='', password='', domain='', hashes=None, aesKey=None, doKerberos=False, kdcHost=None):
        self.dcom = None
        self.iWbemServices = None
        self.target = target
        self.namespace = namespace
        self.username = username
        self.password = password
        self.domain = domain
        self.lmhash = ''
        self.nthash = ''
        self.aesKey = aesKey
        self.doKerberos = doKerberos
        self.kdcHost = kdcHost
        if hashes is not None:
            self.lmhash, self.nthash = hashes.split(':')

    def connect(self):
        try:
            self.dcom = DCOMConnection(self.target, self.username, self.password, self.domain, self.lmhash, self.nthash, self.aesKey, oxidResolver=True, doKerberos=self.doKerberos, kdcHost=self.kdcHost)
            iInterface = self.dcom.CoCreateInstanceEx(wmi.CLSID_WbemLevel1Login, wmi.IID_IWbemLevel1Login)
            iWbemLevel1Login = wmi.IWbemLevel1Login(iInterface)
            self.iWbemServices = iWbemLevel1Login.NTLMLogin(self.namespace, NULL, NULL)
        except socket.error as e:
            logging.error(f"Couldn't connect {self.target}. Error: {str(e)}")
            exit(0)

    def get_reg_hive(self, hive):
        hive_map = {
            'HKCC': 0x80000005,
            'HKU': 0x80000003,
            'HKLM': 0x80000002,
            'HKCU': 0x80000001,
            'HKCR': 0x80000000,
        }
        return hive_map.get(hive, 0x80000002)

    def check_access(self, hive, key_path, check_type):
        hive_num = self.get_reg_hive(hive)
        classObject, _ = self.iWbemServices.GetObject('StdRegProv')
        ret_vals = classObject.CheckAccess(hive_num, key_path, check_type)
        return ret_vals.bGranted
    
    def create_key(self, hive, subkey):
        hive_num = self.get_reg_hive(hive)
        classObject, _ = self.iWbemServices.GetObject('StdRegProv')
        ret_vals = classObject.CreateKey(hive_num, subkey)
        return ret_vals.ReturnValue

    def delete_key(self, hive, subkey):
        hive_num = self.get_reg_hive(hive)
        classObject, _ = self.iWbemServices.GetObject('StdRegProv')
        ret_vals = classObject.DeleteKey(hive_num, subkey)
        return ret_vals.ReturnValue

    def delete_value(self, hive, subkey, value_name):
        hive_num = self.get_reg_hive(hive)
        classObject, _ = self.iWbemServices.GetObject('StdRegProv')
        ret_vals = classObject.DeleteValue(hive_num, subkey, value_name)
        return ret_vals.ReturnValue

    def enum_key(self, hive, key_path):
        hive_num = self.get_reg_hive(hive)
        classObject, _ = self.iWbemServices.GetObject('StdRegProv')
        ret_vals = classObject.EnumKey(hive_num, key_path)
        
        if ret_vals.ReturnValue == 0:
            return ret_vals.sNames or []
        return []

    def enum_values(self, hive, key_path):
        hive_num = self.get_reg_hive(hive)
        classObject, _ = self.iWbemServices.GetObject('StdRegProv')
        ret_vals = classObject.EnumValues(hive_num, key_path)
        
        if ret_vals.ReturnValue != 0:
            return {}

        type_map = {
            1: "REG_SZ",
            2: "REG_EXPAND_SZ",
            3: "REG_BINARY",
            4: "REG_DWORD",
            7: "REG_MULTI_SZ",
            11: "REG_QWORD"
        }

        results = {}
        value_names = ret_vals.sNames or []
        value_types = ret_vals.Types or []
        
        for name, type_num in zip(value_names, value_types):
            value = None
            if type_num == 1:  # String
                value = classObject.GetStringValue(hive_num, key_path, name)
            elif type_num == 2:  # Expanded String
                value = classObject.GetExpandedStringValue(hive_num, key_path, name)
            elif type_num == 3:  # Binary
                value = classObject.GetBinaryValue(hive_num, key_path, name)
            elif type_num == 4:  # DWORD
                value = classObject.GetDWORDValue(hive_num, key_path, name)
            elif type_num == 7:  # Multi-String
                value = classObject.GetMultiStringValue(hive_num, key_path, name)
            elif type_num == 11:  # QWORD
                value = classObject.GetQWORDValue(hive_num, key_path, name)
            
            results[name] = {
                'type': type_map.get(type_num, f"UNKNOWN_{type_num}"),
                'type_num': type_num,
                'value': value.sValue if value and hasattr(value, 'sValue') else value.uValue if value else None
            }
        
        return results

    def get_binary_value(self, hive, key_path, value_name):
        hive_num = self.get_reg_hive(hive)
        classObject, _ = self.iWbemServices.GetObject('StdRegProv')
        ret_vals = classObject.GetBinaryValue(hive_num, key_path, value_name)
        
        if ret_vals.ReturnValue == 0:
            return bytes(ret_vals.uValue)
        return None

    def get_dword_value(self, hive, key_path, value_name):
        hive_num = self.get_reg_hive(hive)
        classObject, _ = self.iWbemServices.GetObject('StdRegProv')
        ret_vals = classObject.GetDWORDValue(hive_num, key_path, value_name)
        if ret_vals.ReturnValue == 0:
            return ret_vals.uValue
        else:
            return None

    def get_expandedstring_value(self, hive, key_path, value_name):
        hive_num = self.get_reg_hive(hive)
        classObject, _ = self.iWbemServices.GetObject('StdRegProv')
        ret_vals = classObject.GetExpandedStringValue(hive_num, key_path, value_name)
        if ret_vals.ReturnValue == 0:
            return ret_vals.sValue
        else:
            return None

    def get_multistring_value(self, hive, key_path, value_name):
        hive_num = self.get_reg_hive(hive)
        classObject, _ = self.iWbemServices.GetObject('StdRegProv')
        ret_vals = classObject.GetMultiStringValue(hive_num, key_path, value_name)
        if ret_vals.ReturnValue == 0:
            return ret_vals.sValue
        else:
            return None

    def get_qword_value(self, hive, key_path, value_name):
        hive_num = self.get_reg_hive(hive)
        classObject, _ = self.iWbemServices.GetObject('StdRegProv')
        ret_vals = classObject.GetQWORDValue(hive_num, key_path, value_name)
        if ret_vals.ReturnValue == 0:
            return ret_vals.uValue
        else:
            return None

    def get_security_descriptor(self, hive, key_path):
        hive_num = self.get_reg_hive(hive)
        classObject, _ = self.iWbemServices.GetObject('StdRegProv')
        ret_vals = classObject.GetSecurityDescriptor(hive_num, key_path)
        if ret_vals.ReturnValue == 0:
            return ret_vals.Descriptor
        else:
            return None
        
    def get_string_value(self, hive, key_path, value_name):
        hive_num = self.get_reg_hive(hive)
        classObject, _ = self.iWbemServices.GetObject('StdRegProv')
        ret_vals = classObject.GetStringValue(hive_num, key_path, value_name)
        
        if ret_vals.ReturnValue == 0:
            return ret_vals.sValue
        return None

    def set_binary_value(self, hive, key_path, value_name, value):
        hive_num = self.get_reg_hive(hive)
        classObject, _ = self.iWbemServices.GetObject('StdRegProv')
        ret_vals = classObject.SetBinaryValue(hive_num, key_path, value_name, value)
        return ret_vals.ReturnValue

    def set_dword_value(self, hive, key_path, value_name, value):
        hive_num = self.get_reg_hive(hive)
        classObject, _ = self.iWbemServices.GetObject('StdRegProv')
        ret_vals = classObject.SetDWORDValue(hive_num, key_path, value_name, value)
        return ret_vals.ReturnValue

    def set_expandedstring_value(self, hive, key_path, value_name, value):
        hive_num = self.get_reg_hive(hive)
        classObject, _ = self.iWbemServices.GetObject('StdRegProv')
        ret_vals = classObject.SetExpandedStringValue(hive_num, key_path, value_name, value)
        return ret_vals.ReturnValue

    def set_multistring_value(self, hive, key_path, value_name, value):
        hive_num = self.get_reg_hive(hive)
        classObject, _ = self.iWbemServices.GetObject('StdRegProv')
        ret_vals = classObject.SetMultiStringValue(hive_num, key_path, value_name, value)
        return ret_vals.ReturnValue

    def set_qword_value(self, hive, key_path, value_name, value):
        hive_num = self.get_reg_hive(hive)
        classObject, _ = self.iWbemServices.GetObject('StdRegProv')
        ret_vals = classObject.SetQWORDValue(hive_num, key_path, value_name, value)
        return ret_vals.ReturnValue

    def set_security_descriptor(self, hive, key_path):
        hive_num = self.get_reg_hive(hive)
        classObject, _ = self.iWbemServices.GetObject('StdRegProv')
        ret_vals = classObject.SetSecurityDescriptor(hive_num, key_path)
        return ret_vals.ReturnValue

    def set_string_value(self, hive, key_path, value_name, value):
        hive_num = self.get_reg_hive(hive)
        classObject, _ = self.iWbemServices.GetObject('StdRegProv')
        ret_vals = classObject.SetStringValue(hive_num, key_path, value_name, value)
        return ret_vals.ReturnValue

    def close(self):
        if self.iWbemServices:
            self.iWbemServices.RemRelease()
        if self.dcom:
            self.dcom.disconnect()

def get_hive(reg_key):
    hives = {
        'HKCU': 'HKCU',
        'HKEY_CURRENT_USER': 'HKCU',
        'HKLM': 'HKLM',
        'HKEY_LOCAL_MACHINE': 'HKLM',
        'HKU': 'HKU',
        'HKEY_USERS': 'HKU',
        'HKCR': 'HKCR',
        'HKEY_CLASSES_ROOT': 'HKCR'
    }
    if ':\\' in reg_key:
        parts = reg_key.split(':\\', 1)
    else:
        parts = reg_key.split('\\', 1)
        
    if len(parts) != 2:
        return None
        
    hive = parts[0].upper()
    key_path = parts[1]

    if hive in hives:
        return [hives[hive], key_path]
    return None

def str_to_bytes(data):
    try:
        data = data.replace(' ', '').replace('0x', '')
        if len(data) % 2 != 0:
            data = '0' + data
        byte_array = bytes.fromhex(data)
        return [b for b in byte_array]
    except ValueError:
        print(f"Error: Invalid hex string: {data}")
        return None

def str_to_dword(data):
    try:
        if data.startswith('0x'):
            return int(data, 16)
        return int(data)
    except ValueError:
        print(f"Error: Invalid DWORD value: {data}")
        return None

def str_to_qword(data):
    try:
        if data.startswith('0x'):
            value = int(data, 16)
        else:
            value = int(data)
        if 0 <= value <= 0xFFFFFFFFFFFFFFFF:
            return value
        else:
            print(f"Error: Value out of range for QWORD (0 to {0xFFFFFFFFFFFFFFFF})")
            return None
            
    except ValueError:
        print(f"Error: Invalid QWORD value: {data}")
        return None

def parse_security_descriptor(descriptor):
    access_rights = {
        0x10000: "DELETE",
        0x20000: "READ_CONTROL",
        0x40000: "WRITE_DAC",
        0x80000: "WRITE_OWNER",
        0x02000: "READ",
        0x04000: "WRITE",
        0x08000: "EXECUTE",
        0xF0000: "ALL_ACCESS"
    }
    ace_types = {
        0: "ACCESS_ALLOWED",
        1: "ACCESS_DENIED",
        2: "SYSTEM_AUDIT",
        3: "SYSTEM_ALARM"
    }
    results = []
    for ace in descriptor.DACL:
        rights = []
        for mask, right in access_rights.items():
            if ace.AccessMask & mask:
                rights.append(right)

        ace_info = {
            'trustee': f"{ace.Trustee.Domain}\\{ace.Trustee.Name}",
            'access_mask': f"0x{ace.AccessMask:08X}",
            'access_rights': rights,
            'ace_type': ace_types.get(ace.AceType, f"Unknown ({ace.AceType})")
        }
        results.append(ace_info)
    return results

def exec_reg(wmi, cmd, reg_key, reg_value, reg_content, access_num):
    print(f'\nAttempting to run {cmd}\n')
    if reg_key:
        reg_data = get_hive(reg_key)
        hive = reg_data[0]
        key_path = reg_data[1]
    else:
        print('Missing -subkey arg')
        return

    if cmd.lower() == 'checkaccess':
        try:
            rt = wmi.check_access(hive, key_path, int(access_num))
            if rt:
                print(f'\nAccess to {reg_key}: {rt}\n')
            else:
                print(f'Access to {reg_key}: {rt}')
                print(f'WMI returned: {rt}')
        except Exception as e:
            print(e)
            return

    elif cmd.lower() == 'createkey':
        try:
            rt = wmi.create_key(hive, key_path)
            if rt:
                print(f'\nSuccessfully created {reg_key}\n')
            else:
                print(f'Failed to create {reg_key}')
                print(f'WMI returned: {rt}')
        except Exception as e:
            print(e)
            return

    elif cmd.lower() == 'deletekey':
        try:
            rt = wmi.delete_key(hive, key_path)
            if rt == 0:
                print(f'\nSuccessfully deleted {reg_key}\n')
            else:
                print(f'Failed to delete {reg_key}')
                print(f'WMI returned: {rt}')
        except Exception as e:
            print(e)
            return

    elif cmd.lower() == 'deletevalue':
        try:
            rt = wmi.delete_value(hive, key_path, reg_value)
            if rt == 0:
                print(f'\nSuccessfully deleted {reg_key}:{reg_value}\n')
            else:
                print(f'Failed to delete {reg_key}:{reg_value}')
                print(f'WMI returned: {rt}')
        except Exception as e:
            print(e)
            return

    elif cmd.lower() == 'enumkey':
        try:
            rt = wmi.enum_key(hive, key_path)
            if len(rt) > 0:
                print(f'\nSubKeyNames for {reg_key}:')
                for keys in rt:
                    print(f'\t{keys}')
                print()
            else:
                print(f'No key data retuend for {reg_key}')
        except Exception as e:
            print(e)
            return

    elif cmd.lower() == 'enumvalues':
        try:
            rt = wmi.enum_values(hive, key_path)
            if len(rt) > 0:
                print(f'\nSubKeyValues for {reg_key}:')
                print(f"\t{'Name':<30}{'Type':<20}Value")
                for name, data in rt.items():
                    print(f'\t{name:<30}{data['type']:<20}{data['value']}')
                print()
            else:
                print(f'No key data returned for {reg_key}')
        except Exception as e:
            print(e)
            return        

    elif cmd.lower() == 'getbinaryvalue':
        try:
            rt = wmi.get_binary_value(hive, key_path, reg_value)
            if rt:
                print(f'Binary value for {reg_key}:{reg_value}')
                print(f'\t{rt}')
            else:
                print(f'No binary value returned for {reg_key}:{reg_value}\n')
        except Exception as e:
            print(e)
            return

    elif cmd.lower() == 'getdwordvalue':
        try:
            rt = wmi.get_dword_value(hive, key_path, reg_value)
            if rt:
                print(f'DWORD value for {reg_key}:{reg_value}')
                print(f'\t{rt}')
            else:
                print(f'No DWORD value returned for {reg_key}:{reg_value}\n')
        except Exception as e:
            print(e)
            return

    elif cmd.lower() == 'getexpandedstringvalue':
        try:
            rt = wmi.get_expandedstring_value(hive, key_path, reg_value)
            if rt:
                print(f'ExpandedString value for {reg_key}:{reg_value}')
                print(f'\t{rt}')
            else:
                print(f'No ExpandedString value returned for {reg_key}:{reg_value}\n')
        except Exception as e:
            print(e)
            return

    elif cmd.lower() == 'getmultistringvalue':
        try:
            rt = wmi.get_multistring_value(hive, key_path, reg_value)
            if rt:
                print(f'MultiString value for {reg_key}:{reg_value}')
                for s in rt:
                    print(f'\t{s}')
            else:
                print(f'No MultiString value returned for {reg_key}:{reg_value}\n')
        except Exception as e:
            print(e)
            return

    elif cmd.lower() == 'getqwordvalue':
        try:
            rt = wmi.get_qword_value(hive, key_path, reg_value)
            if rt:
                print(f'QWORD value for {reg_key}:{reg_value}')
                for s in rt:
                    print(f'\t{s}')
            else:
                print(f'No QWORD value returned for {reg_key}:{reg_value}\n')
        except Exception as e:
            print(e)
            return

    elif cmd.lower() == 'getsecuritydescriptor':
        try:
            rt = wmi.get_security_descriptor(hive, key_path)
            if rt:
                print(f'Security Descriptor value for {reg_key}')
                desc = parse_security_descriptor(rt)
                for ace in desc:
                    print(f"Trustee: {ace['trustee']}")
                    print(f"Access Mask: {ace['access_mask']}")
                    print(f"Rights: {', '.join(ace['access_rights'])}")
                    print(f"ACE Type: {ace['ace_type']}")
                    print("---")
            else:
                print(f'No Security Descriptor value returned for {reg_key}\n')
        except Exception as e:
            print(e)
            return

    elif cmd.lower() == 'getstringvalue':
        try:
            rt = wmi.get_qword_value(hive, key_path, reg_value)
            if rt:
                print(f'String value for {reg_key}:{reg_value}')
                print(f'\t{rt}')
            else:
                print(f'No String value returned for {reg_key}:{reg_value}\n')
        except Exception as e:
            print(e)
            return

    elif cmd.lower() == 'setbinaryvalue':
        try:
            bin_data = str_to_bytes(reg_content)
            rt = wmi.set_binary_value(hive, key_path, reg_value, bin_data)
            if rt == 0:
                print(f'\nSuccessfully set binary value{reg_key}:{reg_value} to {bytes(bin_data)}\n')
            else:
                print(f'WMI Returned: {rt}')
                print(f'Failed to set {reg_key}:{reg_value} to {reg_content}')
        except Exception as e:
            print(e)
            return

    elif cmd.lower() == 'setdwordvalue':
        try:
            dword_data = str_to_dword(reg_content)
            rt = wmi.set_dword_value(hive, key_path, reg_value, dword_data)
            if rt == 0:
                print(f'\nSuccessfully set DWORD value {reg_key}:{reg_value} to {dword_data}\n')
            else:
                print(f'WMI Returned: {rt}')
                print(f'Failed to set {reg_key}:{reg_value} to {dword_data}')
        except Exception as e:
            print(e)
            return
        
    elif cmd.lower() == 'setexpandedstringvalue':
        try:
            rt = wmi.set_expandedstring_value(hive, key_path, reg_value, reg_content)
            if rt == 0:
                print(f'\nSuccessfully set expanded string value {reg_key}:{reg_value} to {reg_content}\n')
            else:
                print(f'WMI Returned: {rt}')
                print(f'Failed to set {reg_key}:{reg_value} to {dword_data}')
        except Exception as e:
            print(e)
            return

    elif cmd.lower() == 'setmultistringvalue':
        try:
            string_list = reg_content.split(',')
            rt = wmi.set_multistring_value(hive, key_path, reg_value, string_list)
            if rt == 0:
                print(f'\nSuccessfully set multi string value {reg_key}:{reg_value} to {reg_content}\n')
            else:
                print(f'WMI Returned: {rt}')
                print(f'Failed to set {reg_key}:{reg_value} to {dword_data}')
        except Exception as e:
            print(e)
            return

    elif cmd.lower() == 'setqwordvalue':
        try:
            qword_data = str_to_qword(reg_content)
            rt = wmi.set_qword_value(hive, key_path, reg_value, qword_data)
            if rt == 0:
                print(f'\nSuccessfully set QWORD value {reg_key}:{reg_value} to {qword_data}\n')
            else:
                print(f'WMI Returned: {rt}')
                print(f'Failed to set {reg_key}:{reg_value} to {dword_data}')
        except Exception as e:
            print(e)
            return

    elif cmd.lower() == 'setsecuritydescriptor':
        print('You want to actually set a security descriptor with this? Come on')
        return

    elif cmd.lower() == 'setstringvalue':
        try:
            rt = wmi.set_string_value(hive, key_path, reg_value, reg_content)
            if rt == 0:
                print(f'\nSuccessfully set string value {reg_key}:{reg_value} to {reg_content}\n')
            else:
                print(f'WMI Returned: {rt}')
                print(f'Failed to set {reg_key}:{reg_value} to {dword_data}')
        except Exception as e:
            print(e)
            return
    else:
        print(f'{cmd} is an invalid option')
        return 

def main():
    parser = argparse.ArgumentParser(add_help=True, description="Registry Snake")
    parser.add_argument('target', action='store', help='[[domain/]username[:password]@]<targetName or address>')
    #parser.add_argument('command', nargs='*', default='', help='registry command to run')
    reg_group = parser.add_argument_group('registry')
    reg_group.add_argument('-command', action='store', help='registry command to run: checkaccess, createkey, deletekey, deletevalue, enumkey, enumvalues,'
                                                            ' getbinaryvalue, getdwordvalue, getexpandedstringvalue, getmultistringvalue, getqwordvalue, getsecuritydescriptor,'
                                                            ' getstringvalue, setbinaryvalue, setdwordvalue, setexpandedstringvalue, setmultistringvalue, setqwordvalue, setsecuritydescriptor, setstringvalue')
    reg_group.add_argument('-subkey', action='store', help='target registry key/subkey to get/set')
    reg_group.add_argument('-valuename', action='store', help='target registry value name to get/set')
    reg_group.add_argument('-value', action='store', help='value to set for a specific valuename')
    reg_group.add_argument('-access_num', action='store', help='int value for access check')
    group = parser.add_argument_group('authentication')
    group.add_argument('-hashes', action="store", metavar="LMHASH:NTHASH", help='NTLM hashes, format is LMHASH:NTHASH')
    group.add_argument('-no-pass', action="store_true", help='don\'t ask for password (useful for -k)')
    group.add_argument('-k', action="store_true",
                       help='Use Kerberos authentication. Grabs credentials from ccache file '
                            '(KRB5CCNAME) based on target parameters. If valid credentials cannot be found, it will use the '
                            'ones specified in the command line')
    group.add_argument('-aesKey', action="store", metavar="hex key", help='AES key to use for Kerberos Authentication '
                                                                          '(128 or 256 bits)')
    group.add_argument('-dc-ip', action='store', metavar="ip address", help='IP Address of the domain controller. If '
                                                                            'ommited it use the domain part (FQDN) specified in the target parameter')
    group.add_argument('-target-ip', action='store', metavar="ip address",
                       help='IP Address of the target machine. If omitted it will use whatever was specified as target. '
                            'This is useful when target is the NetBIOS name and you cannot resolve it')
    

    if len(sys.argv) == 1:
       parser.print_help()
       sys.exit(1)
    options = parser.parse_args()
    if not options.command:
        print('command required')
        return

    wmi_namespace = "//./root/CIMv2"    
    domain, username, password, address = parse_target(options.target)
    
    print(f'\nConnecting to {address}')
    try:
        wmi_obj = WMI(address, wmi_namespace, username, password, domain, options.hashes, options.aesKey, options.k, options.dc_ip)
        wmi_obj.connect()
    except Exception as e:
        print(f'\nFailed to connect: {e}')
        return

    #exec_reg(wmi_obj, options.command[0], options.subkey, options.valuename, options.value)
    exec_reg(wmi_obj, options.command, options.subkey, options.valuename, options.value, options.access_num)

    wmi_obj.close()


if __name__ == "__main__":
    main()
