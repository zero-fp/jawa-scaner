import logging
import re
from collections import defaultdict
from dataclasses import dataclass
from enum import IntEnum

from jawa.classloader import ClassLoader
from jawa.constants import InterfaceMethodRef, MethodReference
from jawa.methods import Method
from typing import List, Set, Tuple
from collections import namedtuple


MethodCallInfo = namedtuple('MethodCallInfo', 'methodName lineNum sourceLine')


class JVMOpcodes(IntEnum):
    INVOKEVIRTUAL = 182
    INVOKESPECIAL = 183
    INVOKESTATIC = 184
    INVOKEINTERFACE = 185
    INVOKEDYNAMIC = 186


INVOKE_OPCODES = {
    JVMOpcodes.INVOKEVIRTUAL,
    JVMOpcodes.INVOKESPECIAL,
    JVMOpcodes.INVOKESTATIC,
    JVMOpcodes.INVOKEINTERFACE,
    JVMOpcodes.INVOKEDYNAMIC,
}


@dataclass(frozen=True)
class CallTarget:
    class_name: str
    method_name: str
    method_type: str


class XrefAnalysis:
    def __init__(self, filename, class_regex, method_regex, caller_method_regex):
        self.class_regex_compiled = re.compile(class_regex)
        self.method_regex_compiled = re.compile(method_regex)
        self.class_loader = ClassLoader(filename)
        self.methods, self.callers = self.traverse(self.class_loader)
        self.lineTable = None
        self.caller_method_regex_compiled = re.compile(caller_method_regex)

    def get_calling_classes(self):
        calling_classes = set()
        for callee, caller_set in self.callers.items():
            if self.class_regex_compiled.match(
                    callee.class_name
            ) and self.method_regex_compiled.match(callee.method_name):
                calling_classes |= caller_set
        return calling_classes

    @staticmethod
    def method_ref_to_call_target(method_ref):
        if method_ref and isinstance(method_ref, (MethodReference, InterfaceMethodRef)):
            return CallTarget(
                method_ref.class_.name.value,
                method_ref.name_and_type.name.value,
                method_ref.name_and_type.descriptor.value,
            )
        return None

    def traverse(self, classloader: ClassLoader):
        call_targets = {}
        methods = {}
        callers = defaultdict(set)
        for class_name in classloader.classes:
            try:
                classloader[class_name]
            except IndexError:
                continue
            (
                call_targets[class_name],
                methods[class_name],
            ) = self.summarize_class(classloader[class_name])

        for class_name, class_call_targets in call_targets.items():
            for call_target in class_call_targets:
                callers[call_target].add(class_name)

        return methods, callers

    def summarize_class(self, classfile) -> Tuple[Set[CallTarget], List[Method]]:
        class_callees: Set[CallTarget] = set()
        for const in classfile.constants:
            call_target = self.method_ref_to_call_target(const)
            if call_target:
                class_callees.add(call_target)
        methods = list(classfile.methods)
        return class_callees, methods

    def load_lineNumberTable(self, method):
        code_attr = method.attributes.find_one(name='Code')
        if not code_attr:
            self.lineTable = None
            return
        numbertable_attr = code_attr.attributes.find_one(name='LineNumberTable')
        self.lineTable = numbertable_attr
        return

    def convert_to_linenum(self, pc_addr):
        if not self.lineTable:
            return -1
        # get line num
        i = 0
        while i + 1 < len(self.lineTable.line_no):
            line_number_entry_1, line_number_entry_2 = self.lineTable.line_no[i], self.lineTable.line_no[i + 1]
            if line_number_entry_1.start_pc <= pc_addr < line_number_entry_2.start_pc:
                return line_number_entry_1.line_number
            i += 1
        return self.lineTable.line_no[i - 1].line_number

    def analyze_class(self, classname):
        all_xrefs = set()
        xref_constants = defaultdict(set)
        calling_methods_by_target = defaultdict(set)
        for method in self.methods[classname]:
            if not re.match(self.caller_method_regex_compiled, method.name.value):
                continue
            self.load_lineNumberTable(method)
            callsites = self.callsites_in_method(method)
            if not callsites:
                continue
            new_xrefs, xref_pc_set = callsites
            if not new_xrefs:
                continue
            for xref, pc in xref_pc_set:
                xref_constants[xref].add(MethodCallInfo(method.name.value, self.convert_to_linenum(pc), 'null\n'))
            all_xrefs |= new_xrefs

        interesting_xrefs = {}
        for xref in all_xrefs:
            call_target = self.method_ref_to_call_target(
                self.class_loader[classname].constants.get(xref)
            )
            if call_target:
                if self.class_regex_compiled.match(
                        call_target.class_name
                ) and self.method_regex_compiled.match(call_target.method_name):
                    interesting_xrefs[xref] = call_target

        for xref in interesting_xrefs:
            calling_methods_by_target[interesting_xrefs[xref]] |= xref_constants[xref]
        return calling_methods_by_target

    def callsites_in_method(self, method: Method):
        if not method.code:
            return
        method_code = method.code.disassemble()
        xref_set = set()
        xref_pc_value = set()
        for op in method_code:
            if op.opcode not in INVOKE_OPCODES:
                continue
            xref_set.add(op.operands[0].value)
            xref_pc_value.add((op.operands[0].value, op.pos))
        return xref_set, xref_pc_value


class JawaScanner:
    def __init__(self):
        self.for_json_save = {}

    def get_caller_results(self, class_name, calling_methods_by_target):
        if calling_methods_by_target:
            # collapse method types:
            calling_methods_collapsed = {
                CallTarget(ct.class_name, ct.method_name, ""): calling_methods_by_target[ct]
                for ct in calling_methods_by_target
            }

            calls_info_dict = {}
            for callee, callers in calling_methods_collapsed.items():
                calls_info_dict[callee.class_name.replace('/', '.') + '.' + callee.method_name] = list(callers)
            self.for_json_save[class_name] = calls_info_dict

    def print_xrefs_analysis(self, xref_analysis):
        for classname in xref_analysis.get_calling_classes():
            calling_methods_by_target = xref_analysis.analyze_class(classname)
            if calling_methods_by_target:
                self.get_caller_results(classname, calling_methods_by_target)

    def run(self, file_to_scan, class_regex, method_regex, caller_method):
        self.for_json_save = {}
        try:
            xref_analysis = XrefAnalysis(file_to_scan, class_regex, method_regex, caller_method)
            self.print_xrefs_analysis(xref_analysis)
        except ValueError as e:
            logging.error(f"Parsing error in {file_to_scan}")
