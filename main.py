import json
import logging
import os
import shutil
import subprocess
import sys
import zipfile

from pathlib import Path
import argparse

from jawa_scanner import JawaScanner
from json_manager import JsonExporter

from deps_manager import DepsManager, rreplace


def jd_core_decompiler(jar_file):
    JD_CORE_PATH = os.path.join(os.path.dirname(__file__), "resources", "jd-cli.jar")
    workfiles_dir = os.path.join(os.path.dirname(__file__), "source")
    if os.path.exists(workfiles_dir):
        shutil.rmtree(workfiles_dir)
    os.makedirs(workfiles_dir)
    try:
        subprocess.run(['java', '-jar', JD_CORE_PATH, '-n', '-od', workfiles_dir, jar_file], stdout=subprocess.DEVNULL,
                       stderr=subprocess.DEVNULL, timeout=120)
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
        return ''
    return os.path.join(workfiles_dir)


class Runner:
    NO_SOURCE = 0
    SOURCE_DECOMPILE = 1
    SOURCE_DOWNLOAD = 2

    def __init__(self):
        self.check_fatjar = None
        self.deps_manager = DepsManager()
        self.source_dir = os.path.join(os.path.abspath(os.path.dirname(__file__)), 'source')
        self.source_status = Runner.NO_SOURCE
        self.scanner = JawaScanner()

    def get_jar_source(self, jar_filename, package_name):
        self.source_status = Runner.NO_SOURCE
        # call decompiler
        if package_name == 'None':
            if not os.path.exists(jar_filename):
                return None
            self.source_status = Runner.SOURCE_DECOMPILE
            return jd_core_decompiler(jar_filename)

        # try download source
        source_coordinate_str = self.deps_manager.get_source_coordinate_str_from_packagename(package_name)
        rc = self.deps_manager.download_artifact(source_coordinate_str)
        source_jar_filename = self.deps_manager.get_jar_from_coordinate_str(source_coordinate_str)
        if rc and not os.path.exists(source_jar_filename):
            # try decompile
            if not os.path.exists(jar_filename):
                return None
            else:
                self.source_status = Runner.SOURCE_DECOMPILE
                return jd_core_decompiler(jar_filename)
        else:
            # unzip source.jar
            shutil.rmtree(self.source_dir, ignore_errors=True)
            jar_source_folder = os.path.join(self.source_dir, os.path.basename(source_jar_filename).replace('.', '-'))
            os.makedirs(jar_source_folder, exist_ok=True)
            try:
                with zipfile.ZipFile(source_jar_filename, "r") as zip_ref:
                    zip_ref.extractall(jar_source_folder)
                    self.source_status = Runner.SOURCE_DOWNLOAD
                    return jar_source_folder
            except zipfile.BadZipFile:
                return None

    def extract_source_line(self, source_folder, class_fqn, line_number):
        pos = class_fqn.find('$')
        if pos != -1:  # replace inner class name
            class_fqn = class_fqn[0: pos]
        java_source_file = os.path.join(source_folder, class_fqn + '.java')
        if not os.path.exists(java_source_file):
            logging.debug('Source {:s} not found'.format(java_source_file))
            return 'null\n'
        with open(java_source_file, 'r') as fh:
            arr = fh.readlines()
            if self.source_status == Runner.SOURCE_DOWNLOAD:
                return arr[line_number - 1]
            elif self.source_status == Runner.SOURCE_DECOMPILE:
                for line in arr:
                    pos = line.find('*/')
                    prefix = line[0: pos]
                    if prefix.find(' ' + str(line_number) + ' ') != -1:
                        return line
            else:
                return 'null\n'

    def run_jawa_on_package(self, gav) -> str:
        coordinate_str = self.deps_manager.get_coordinate_str_from_packagename(gav)
        jar_file = self.deps_manager.get_jar_from_coordinate_str(coordinate_str)
        if not os.path.exists(jar_file):
            self.deps_manager.download_artifact(gav)
        if not os.path.exists(jar_file):
            return json.dumps({'gav': gav, 'status': 'mvn download error'})
        return self.run_jawa_on_jar(jar_file, gav)

    def run_jawa_on_jar(self, jar_file, gav='None'):
        if os.path.exists(jar_file):
            # if self.check_fatjar and test_log4j_fatjar(jar_file):
            #    return json.dumps({'gav': gav, 'status': 'fatjar'})
            try:
                self.scanner.run(jar_file, self.class_regex, self.method_regex, self.caller_method_regex)
            except zipfile.BadZipFile:
                return json.dumps({'gav': gav, 'status': 'bad zipfile'})

            if self.scanner.for_json_save:
                source_folder = self.get_jar_source(jar_file, gav)
                if not source_folder:
                    return json.dumps({'gav': gav, 'status': "source code error"})
                # add code line
                for className, calls in self.scanner.for_json_save.items():
                    for callee, rows in calls.items():
                        for i, callInfo in enumerate(rows):
                            if callInfo.lineNum != -1:
                                rows[i] = callInfo._replace(
                                    sourceLine=self.extract_source_line(source_folder, className, callInfo.lineNum))
                # add source status info
                if self.source_status == Runner.SOURCE_DECOMPILE:
                    src_status_str = 'decompile'
                elif self.source_status == Runner.SOURCE_DOWNLOAD:
                    src_status_str = 'download'
                else:
                    src_status_str = 'error'

                return json.dumps({'gav': gav, 'status': 'ok', 'jar': jar_file, 'source': src_status_str,
                                   'result': self.scanner.for_json_save})
            else:
                return json.dumps({'gav': gav, 'status': 'nothing found'})
        else:
            return json.dumps({'gav': gav, 'status': 'jar not found'})

    def run(self):
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers(dest="command")
        scan_command = subparsers.add_parser("scan", help='Scan packages or jar files')
        export_command = subparsers.add_parser("export", help='Pretty-print results')

        scan_command.add_argument('--package', required=False, default='', type=str, help='Package in format g:a:v')
        scan_command.add_argument('--package-list', required=False, default='', type=str, help='Package list')
        scan_command.add_argument('--jar', required=False, default='', type=str, help='Path to .jar file for scan')
        scan_command.add_argument('--jar-list', required=False, default='', type=str,
                                  help='List of .jar files for scan')
        scan_command.add_argument('--scan-local-maven', required=False, default=False, action='store_true',
                                  help='Scan all packages in local Maven repository')
        # scan_command.add_argument('--check-fatjar', required=False, default=False, action='store_true',
        #                           help='Check fatjar or no')
        scan_command.add_argument('--class-regex', required=False, default='.*', type=str,
                                  help='Regex for class-name to search calls')
        scan_command.add_argument('--method-regex', required=False, default='.*', type=str,
                                  help='Regex for method-name to search calls')
        scan_command.add_argument('--caller-method-regex', required=False, default='.*', type=str,
                                  help='Regex for caller method where calls search is done')
        scan_command.add_argument('--out-filename', required=False, default='', type=str, help='Filename for output')

        export_command.add_argument('--scan-json', required=False, default='', type=str,
                                    help='Filename with json, generated with "scan" command')
        export_command.add_argument('--pvf-method-list', required=False, default='', type=str,
                                    help='List of method signatures to filter')
        export_command.add_argument('--caller-method-regex', required=False, default='.*', type=str,
                                    help='Regex for caller method to filter')
        export_command.add_argument('--out-filename', required=False, default='', type=str, help='Filename for output')

        args = parser.parse_args()
        if not args.command:
            parser.parse_args(["--help"])
            sys.exit(0)

        if args.command == 'scan':
            if not any([args.package, args.package_list, args.jar, args.jar_list, args.scan_local_maven]):
                parser.parse_args(["scan", "--help"])
                sys.exit(0)

            self.class_regex = args.class_regex
            self.method_regex = args.method_regex
            self.caller_method_regex = args.caller_method_regex

            if args.out_filename:
                logging.basicConfig(filename=args.out_filename, filemode='w', format='%(message)s', level=logging.INFO)
            else:
                logging.basicConfig(format='%(message)s', stream=sys.stdout, level=logging.INFO)

            if args.package:
                logging.info(self.run_jawa_on_package(args.package))
            elif args.package_list:
                if not os.path.exists(args.package_list):
                    logging.warning('Package list file not found')
                    sys.exit(0)
                with open(args.package_list, 'r') as fh:
                    for line in fh.readlines():
                        logging.info(self.run_jawa_on_package(line.strip()))
            elif args.jar:
                logging.info(self.run_jawa_on_jar(args.jar))
            elif args.jar_list:
                if not os.path.exists(args.jar_list):
                    logging.warning('Jar list file not found')
                    sys.exit(0)
                with open(args.jar_list, 'r') as fh:
                    for line in fh.readlines():
                        logging.info(self.run_jawa_on_jar(line.strip()))
            elif args.scan_local_maven:
                local_repo = Path(os.path.join(os.path.expanduser('~'), '.m2'))
                for jar_path in local_repo.rglob('*.jar'):
                    jar_path_str = str(jar_path)
                    if jar_path_str.endswith('-sources.jar'):
                        continue
                    pom_path = rreplace(jar_path_str, '.jar', '.pom')
                    gav = DepsManager.get_gav_from_pom(pom_path)
                    if len(gav.split(':')) == 3:
                        logging.info(self.run_jawa_on_jar(jar_path_str, gav))
                    else:
                        logging.info(self.run_jawa_on_jar(jar_path_str))

        elif args.command == 'export':
            if not args.scan_json:
                parser.parse_args(["export", "--help"])
                sys.exit(0)

            if args.out_filename:
                logging.basicConfig(filename=args.out_filename, filemode='w', format='%(message)s', level=logging.INFO)
            else:
                logging.basicConfig(format='%(message)s', stream=sys.stdout, level=logging.INFO)

            pvf_method_list_file = args.pvf_method_list
            if pvf_method_list_file:
                if not os.path.exists(pvf_method_list_file):
                    logging.warning('PVF list file not found')
                    sys.exit(0)
                with open(pvf_method_list_file, 'r') as fh:
                    filter_methodlist = list(map(lambda x: x.strip(), fh.readlines()))
            else:
                filter_methodlist = []
            JsonExporter(args.scan_json, args.caller_method_regex, filter_methodlist).pretty_print_all()


if __name__ == "__main__":
    Runner().run()
