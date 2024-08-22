import logging
import os
import subprocess

from neo4j import GraphDatabase

NEO4J_URI = "bolt://127.0.0.1:7687"
NEO4J_LOGIN = 'neo4j'  # your neo4j login here
NEO4J_PASSWORD = '12345678'  # your neo4j password here


def rreplace(s, old, new):
    li = s.rsplit(old, 1)
    return new.join(li)


class DepsManager:
    def __init__(self):
        self.cp_path = '/tmp/cp.txt'
        self.maven_repo_path = os.path.expanduser("~") + "/.m2/repository"
        self.scope = ''

    @staticmethod
    def get_coordinate_str_from_packagename(package):
        parts = package.split(':')
        if len(parts) > 3:
            group_id, artifact_id, version = parts[0], parts[1], parts[3]
        else:
            group_id, artifact_id, version = parts[0], parts[1], parts[2]

        jar_coordinate_str = "{:s}:{:s}:jar:{:s}".format(group_id, artifact_id, version)
        return jar_coordinate_str

    @staticmethod
    def get_source_coordinate_str_from_packagename(package):
        parts = package.split(':')
        if len(parts) > 3:
            group_id, artifact_id, version = parts[0], parts[1], parts[3]
        else:
            group_id, artifact_id, version = parts[0], parts[1], parts[2]
        source_coordinate_str = "{:s}:{:s}:jar:sources:{:s}:scope".format(group_id, artifact_id, version)
        return source_coordinate_str

    def get_jar_from_coordinate_str(self, coordinate_str):
        parts = coordinate_str.split(':')

        if len(parts) > 3:
            group_id, artifact_id, packaging = parts[0].replace('.', '/'), parts[1], parts[2]
        else:
            return None

        if len(parts) == 4:
            version = parts[3]
            basename = f"{artifact_id}-{version}.{packaging}"
        elif len(parts) == 5:
            version, scope = parts[3], parts[4]
            basename = f"{artifact_id}-{version}.{packaging}"
        elif len(parts) == 6:
            classifier, version, scope = parts[3], parts[4], parts[5]
            basename = f"{artifact_id}-{version}-{classifier}.{packaging}"

        file_path = f"{self.maven_repo_path}/{group_id}/{artifact_id}/{version}/{basename}"
        return file_path

    @staticmethod
    def get_gav_from_pom(pom_path):
        stdin_str = '${project.groupId}:${project.artifactId}:${project.version}'
        pom_path, pom_basename = os.path.dirname(pom_path), os.path.basename(pom_path)
        p = subprocess.run(
            ['mvn', 'org.apache.maven.plugins:maven-help-plugin:3.2.0:evaluate', '-f', pom_basename, '-q',
             '-DforceStdout'], input=stdin_str, capture_output=True, text=True, cwd=pom_path)
        out = p.stdout.strip()
        if out.find('[ERROR]') != -1:
            return ''
        return out

    def download_artifact(self, gav, transitive=False):
        try:
            cmd = ['mvn', 'dependency:get']
            if not transitive:
                cmd.append('-Dtransitive=false')
            cmd.append('-Dartifact={:s}'.format(gav))
            rc = subprocess.call(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT, timeout=180)
            return rc
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
            logging.debug(f'Timeout for {gav}')
            return 1

