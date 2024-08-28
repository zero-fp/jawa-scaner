import re
import json
import copy


signature_regexp_str = "<([^:\s]+): ([\S]+) ([^\(\s]+)\((.*)\)>"
SIGNATURE_REGEXP = re.compile(signature_regexp_str)


def parse_signature_to_fqn(signature):
    match = SIGNATURE_REGEXP.search(signature)
    return match.group(1) + '.' + match.group(3)


class JsonExporter:
    def __init__(self, scan_json, caller_regex, filter_methodlist):
        self.scan_json = scan_json
        self.caller_regex = re.compile(caller_regex)
        self.filter_methodlist = list(map(lambda x: parse_signature_to_fqn(x.strip()) if x.find('<') != -1 else x, filter_methodlist))

        self.data = {}
        self.packageList = []
        with open(self.scan_json, 'r') as fh:
            for line in fh.readlines():
                json_line = line.strip()
                if not json_line:
                    continue
                arr = json.loads(json_line.strip())
                key = arr['gav']
                self.data[key] = arr
                self.packageList.append(key)
        self.packageList.sort()

    def pretty_print_all(self):
        for gav in self.packageList:
            arr = self.data[gav]
            if arr['status'] != 'ok':
                continue
            filteredArr = self.get_filtered_methods(arr)
            if len(filteredArr['result']):
                print('PACKAGE: {:s}\nJar: {:s}\n'.format(arr['gav'], arr['jar']))
                print(self.pretty_print_package(filteredArr))
                print('=' * 20)

    def pretty_print_package(self, arr):
        temp_out = ''
        for className, rows in arr['result'].items():
            call_info_str = []
            for callee, callInfo in rows.items():
                for tuple_ in callInfo:
                    if len(tuple_) == 3:
                        call_info_str.append('CALL: ' + callee + '\n' + str(tuple_[1]) + '\t' + (tuple_[2] if tuple_[2] else 'null\n'))
            if call_info_str:
                temp_out += 'CLASSNAME: {:s}\n{:s}\n'.format(className, "".join(call_info_str))
        return temp_out

    def check_methods_found(self, gav):
        return gav in self.data.keys() and 'result' in self.data[gav].keys() and self.data[gav]['result']

    def get_filtered_methods(self, arr):
        if arr['status'] != 'ok':
            return []
        new_arr = copy.deepcopy(arr)
        for className, rows in arr['result'].items():
            for callee, callInfo in rows.items():
                if self.filter_methodlist and callee not in self.filter_methodlist:
                    del new_arr['result'][className][callee]
                    continue
                new_arr['result'][className][callee] = list(filter(lambda x: self.caller_regex.match(x[0]), callInfo))
            if len(new_arr['result'][className]) == 0:
                del new_arr['result'][className]
        return new_arr