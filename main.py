import logging
import argparse
import sys
import socket
from logging.handlers import RotatingFileHandler
from time import sleep
import time

import pymysql as pymysql
from ldap3 import Server, Connection, ALL
import subprocess

from ozpy.zmprov import Zmprov
import paramiko
from configobj import ConfigObj
from subprocess import run, PIPE

CONFIG = ConfigObj("mailboxmove.conf")

OFFSET_MAILBOX_ID = int(CONFIG["zimbra-config"]["offset_mailbox_id"])
ldap_server = CONFIG["zimbra-config"]['ldap_server']
ldap_port = int(CONFIG["zimbra-config"]['ldap_port'])
ldap_user = CONFIG["zimbra-config"]['ldap_user']
ldap_password = CONFIG["zimbra-config"]['ldap_password']

ZADMIN_USERNAME = CONFIG["zimbra-config"]['ZADMIN_USERNAME']
ZADMIN_PASSWORD = CONFIG["zimbra-config"]['ZADMIN_PASSWORD']
ZSTORE = CONFIG["zimbra-config"]['ZSTORE']

TMP_PATH = '/var/tmp/'
LOG_PATH = '/tmp/'

ZADMIN_SOAP_URL = "https://" + ZSTORE + ":7071/service/admin/soap"
ALL_MAILBOX_TABLES = ['appointment',
                      'data_source_item',
                      'imap_folder',
                      'imap_message',
                      'mail_item',
                      'tag',
                      'tagged_item',
                      'open_conversation',
                      'pop3_message',
                      'purged_conversations',
                      'purged_messages',
                      'revision',
                      'revision_dumpster',
                      'mail_item_dumpster',
                      'appointment_dumpster',
                      'tombstone']

server = Server(ldap_server, port=ldap_port, get_info=ALL)
conn = Connection(server, user=ldap_user, password=ldap_password, auto_bind=True)

all_stores = dict()

all_stores = CONFIG['store-config']

status_value = {
    'Succeeded': 0,
    'warning': 1,
    'fail': 2
}


def getLogLevel(argument):
    switcher = {
        'INFO': logging.INFO,
        'WARNING': logging.WARNING,
        'DEBUG': logging.DEBUG,
    }
    return switcher.get(argument, logging.DEBUG)


logger = logging.getLogger()
logger.setLevel(getLogLevel('DEBUG'))
formatter = logging.Formatter('%(asctime)s :: %(levelname)s :: %(message)s')
file_handler = RotatingFileHandler(CONFIG['global']['log_file'], 'a', 100000000, 100)
file_handler.setLevel(getLogLevel('DEBUG'))
file_handler.setFormatter(formatter)
logger.addHandler(file_handler)
steam_handler = logging.StreamHandler()
steam_handler.setLevel(getLogLevel('INFO'))
logger.addHandler(steam_handler)

logger.debug("Starting Logger...")




def transform_output_to_dict(output):
    new_dict = {}
    for item in output:
        name = item['n']
        if name in new_dict:
            first_value = new_dict[name]
            if type(new_dict[name]) is not list:
                new_dict[name] = list()
                new_dict[name].append(first_value)
            new_dict[name].append(item['_content'])
        else:
            new_dict[name] = item['_content']

    return new_dict


def create_folder(path):
    status, output = subprocess.Popen("mkdir -p {}".format(path), shell=True, stdout=subprocess.PIPE)

    if status == 0:
        logger.info('[RSYNC-PREP] - Creating path {} [OK]'.format(path))
        return True
    logger.error('[PREP] - Creating path {} [Failed] due to {}'.format(path, output))
    return False


def create_remote_folder(hostname, dest_dir):
    logger.info(f'[REMOTE-SSH][{hostname}] - Creating path {dest_dir} ')
    username = 'root'
    port = 22
    # Create SSH client object
    ssh_client = paramiko.SSHClient()

    # Automatically add host keys from known hosts file
    ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    # Connect to remote server
    ssh_client.connect(hostname=hostname, port=port, username=username)

    # Create remote directory

    stdin, stdout, stderr = ssh_client.exec_command('mkdir -p {}'.format(dest_dir))

    # Get output and error
    output = stdout.read().decode('utf-8')
    error = stderr.read().decode('utf-8')

    # Print output and error
    logger.debug(f'[REMOTE-SSH][{hostname}] - Creating path output={output} ')
    if len(error) > 0:
        logger.error(f'[REMOTE-SSH][{hostname}] - Creating path error={error} ')

    # Close SSH connection
    ssh_client.close()


def flush_memcached(hostname):
    logger.info(f'[REMOTE-SSH][{hostname}] - flushing memecache ')
    username = 'root'
    port = 22
    # Create SSH client object
    ssh_client = paramiko.SSHClient()

    # Automatically add host keys from known hosts file
    ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    # Connect to remote server
    ssh_client.connect(hostname=hostname, port=port, username=username)

    # Create remote directory

    stdin, stdout, stderr = ssh_client.exec_command("echo 'flush_all' | nc localhost 11211")

    # Get output and error
    output = stdout.read().decode('utf-8')
    error = stderr.read().decode('utf-8')

    # Print output and error
    logger.debug(f'[REMOTE-SSH][{hostname}] - Flushing memecache output = {output} ')

    if len(error) > 0:
        logger.error(f'[REMOTE-SSH][{hostname}] - Flushing memecache error = {error} ')
        return False
    # Close SSH connection
    ssh_client.close()

    return True


def flush_zcs_cache(hostname):
    logger.info(f'[REMOTE-SSH][{hostname}] - flushing zcs cache ')
    username = 'root'
    port = 22
    # Create SSH client object
    ssh_client = paramiko.SSHClient()

    # Automatically add host keys from known hosts file
    ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    # Connect to remote server
    ssh_client.connect(hostname=hostname, port=port, username=username)

    # Create remote directory

    stdin, stdout, stderr = ssh_client.exec_command("/opt/zimbra/bin/zmprov fc all")

    # Get output and error
    output = stdout.read().decode('utf-8')
    error = stderr.read().decode('utf-8')

    # Print output and error
    logger.debug(f'[REMOTE-SSH][{hostname}] - Flushing ZCS Cache output = {output} ')

    if len(error) > 0:
        logger.error(f'[REMOTE-SSH][{hostname}] - Flushing ZCS Cache error = {error} ')
        return False
    # Close SSH connection
    ssh_client.close()

    return True


def create_ssh_tunnel(ssh_server, local_port, remote_port=7306):
    ssh_port = 22
    ssh_user = 'root'

    ssh_remote_bind_address = 'localhost:7306'
    ssh_local_bind_address = f'localhost:{local_port}'

    # Execute the SSH command to create the tunnel
    ssh_command = f'ssh -L {ssh_local_bind_address}:{ssh_remote_bind_address}' \
                  f' {ssh_user}@{ssh_server} -p {ssh_port}'

    ssh_process = subprocess.Popen(ssh_command.split(), stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    logger.info(f"[MYSQL_TUNNEL] - Tunnel created: localhost:{local_port} -> '{ssh_server}':{remote_port}")
    logger.info(f"[MYSQL_TUNNEL] -LISTENING MODE STARTED")
    ssh_process.communicate()
    # Print the output of the SSH command
    # output, error = ssh_process.communicate()


def get_zmhostname():
    zimbra_command = "/opt/zimbra/bin/zmhostname"

    output = subprocess.check_output(zimbra_command.split())
    output_str = output.decode('utf-8')
    return output_str


def get_account(email):
    logger.info("getting account attr for " + email)
    zmprov = Zmprov(
        username=ZADMIN_USERNAME,
        password=ZADMIN_PASSWORD,
        soapurl=ZADMIN_SOAP_URL,
        timeout=30
    )
    output = str()
    try:
        output = zmprov.ga(email)
    except Exception as e:
        logger.error("zmprov fail to obtain information for {} cause = {}".format(email, e))
        return False
    if not output:
        logger.error("error when  getting account's attr for " + email)
        return False

    return transform_output_to_dict(output)


def modify_account(zimbraId, **attr):
    zmprov = Zmprov(
        username=ZADMIN_USERNAME,
        password=ZADMIN_PASSWORD,
        soapurl=ZADMIN_SOAP_URL,
        timeout=30
    )
    logger.info(f'[{zimbraId}] - Modify attributes ')
    for attribute, value in attr.items():
        logger.info(f'[{zimbraId}] - Modifying user ' + zimbraId + ' setting ' + attribute + '=' + value)
        output = str()
        try:
            output = zmprov.ma(zimbraId, attribute, value)
        except Exception as e:
            logger.error("zmprov fail to modify account related attribute {attribute} for {} cause = {}".
                         format(attribute, zimbraId, e))
            return False
        if not output:
            logger.error(f"[{zimbraId}] - Can't modify attribute " + attribute + " with value = " + value)
            return False
    return True


def modify_account_multi(zimbraId, operator, **attr):
    zmprov = Zmprov(
        username=ZADMIN_USERNAME,
        password=ZADMIN_PASSWORD,
        soapurl=ZADMIN_SOAP_URL,
        timeout=30
    )
    logger.info("modify attribute mutli")
    for attribute, value in attr.items():
        output = zmprov.ma(zimbraId, operator + attribute, value)
        if not output:
            logger.error("can't modify attribute " + attribute + " with value = " + value + " operation=" + operator)
            return False
    return True


def get_attribute(email, attribute):
    result = str()
    try:
        result = get_account(email)[attribute]
    except:
        logger.error(f"Unable to get this {attribute} for {email}")
        return None
    return result


def get_zimbraId(email):
    zimbraId = get_attribute(email, 'zimbraId')
    if zimbraId is None:
        logger.error(f"Something wrong with {email} please check this account with zmprov ga")
        return None
    logger.info(f"[{email}] - get attribute zimbraId={zimbraId} ")
    return zimbraId


def get_ZimbraMailHost(email):
    logger.info(f"[{email}] - get attribute zimbraMailHost ")
    zimbraMailHost = get_attribute(email, 'zimbraMailHost')
    logger.info(f"[{email}] - get attribute zimbraMailHost={zimbraMailHost} ")
    return zimbraMailHost


def connect_and_push(store_db_info, db, query, force_mode):
    logger.debug(f"[DB-COMMIT][{store_db_info['host']}][{store_db_info['port']}][{db}] - query = {query}")
    logger.debug(f"[DB-COMMIT][{store_db_info['host']}][{store_db_info['port']}][{db}] COMMIT To  database")
    if len(query) == 0:
        logger.debug(f"[DB-COMMIT][{store_db_info['host']}][{store_db_info['port']}][{db}] - query EMPTY")
        return True
    connection = pymysql.connect(host=store_db_info['host'], port=int(store_db_info['port']),
                                 user=store_db_info['user'],
                                 password=store_db_info['password'],
                                 db=db,
                                 charset='utf8mb4',
                                 cursorclass=pymysql.cursors.DictCursor)

    try:
        cursor = connection.cursor()
        cursor.execute(query)
        connection.commit()

    except Exception as e:
        logger.error(
            f"[DB-COMMIT][{store_db_info['host']}][{db}] Insert to database"
            f" query = {query} failed cause : {e} ")
        if "Duplicate entry " in str(e) and force_mode:
            logger.debug(
                f"[DB-COMMIT][{store_db_info['host']}][{store_db_info['port']}][{db}] - Forcing mode continue...")
            return True
        return False

    finally:
        connection.close()

    return True


def connect_and_get(store_db_info, db, query):
    logger.debug(f"[DB-GET][{store_db_info['host']}][{store_db_info['port']}][{db}] - query = {query}")
    logger.debug(f"[DB-GET][{store_db_info['host']}][{store_db_info['port']}][{db}] connect to database")

    result = None
    connection = pymysql.connect(host=store_db_info['host'], port=int(store_db_info['port']),
                                 user=store_db_info['user'],
                                 password=store_db_info['password'],
                                 db=db,
                                 charset='utf8mb4',
                                 cursorclass=pymysql.cursors.DictCursor)

    try:
        cursor = connection.cursor()
        cursor.execute(query)
        result = cursor.fetchall()

    except Exception as e:
        logger.error(
            f"[DB-GET][{store_db_info['host']}][{store_db_info['port']}][{db}] "
            f"Insert to database query = {query} failed cause : {e} ")

    finally:
        connection.close()

    logger.debug(f"[DB-GET][{store_db_info['host']}][{store_db_info['port']}][{db}] - result for  {query} = {result}")
    return result


def get_mailbox_id(store_db_info, email):
    result = connect_and_get(store_db_info, 'zimbra',
                             'select id from mailbox where comment like \'{}\' '.format(email))
    try:
        return str(result[0]['id'])
    except IndexError:
        return None


def is_mailbox_id_exists(store_db_info, id_):
    result = connect_and_get(store_db_info, 'zimbra',
                             'select id from mailbox where id={} '.format(id_))

    if len(result) > 0:
        return True
    return False


def query_ldap(base_dn='', search_filter=None, search_attributes=None):
    conn.search(base_dn, search_filter, attributes=search_attributes)
    results = conn.entries

    return results


def get_all_proxy_servers():
    result = query_ldap(search_filter='(zimbraServiceInstalled=proxy)', search_attributes=['cn', 'zimbraId'])
    all_proxys = list()
    for proxy in result:
        all_proxys.append(str(proxy.cn))
    return all_proxys


def get_all_store_servers():
    result = query_ldap(search_filter='(zimbraServiceInstalled=mailbox)', search_attributes=['cn', 'zimbraId'])
    all_stores = list()
    for store in result:
        all_stores.append(str(store.cn))
    return all_stores


def flush_cache_all_stores():
    for store in get_all_store_servers():
        if not flush_zcs_cache(store):
            return False
    return True


def rsync(src_server, src_dir, dst_server, dst_dir, user):
    logger.info(
        f"[RSYNC][{user.email}] - from {src_server} for path {src_dir} to remote {dst_server} to path {dst_dir} started")

    # Define rsync command
    rsync_cmd = ['rsync', '--archive', '--copy-links', f'{src_dir}', f'{dst_server}:{dst_dir}']

    # Call rsync command
    process = subprocess.Popen(rsync_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    # Get output and error
    output, error = process.communicate()

    logger.info(
        f"[RSYNC] - from {src_server} for path {src_dir} to remote {dst_server} to path {dst_dir} output={output.decode('utf-8')}")
    logger.info(
        f"[RSYNC] - from {src_server} for path {src_dir} to remote {dst_server} to path {dst_dir} error={error.decode('utf-8')}")
    if len(error.decode('utf-8')) > 0:
        return False
    logger.info(
        f"[RSYNC][{user.email}] - from {src_server} for path {src_dir} to remote {dst_server} to path {dst_dir} finished")
    return True


def get_dump(store_mysql_conn, db, table, where, user):
    tmp_file = f'{TMP_PATH}{user.zimbraId}.{table}.sql.orig'
    mysqldump_cmd = ['/opt/zimbra/common/bin/mysqldump', '--host=127.0.0.1',
                     '-P', store_mysql_conn['port'],
                     '-u', 'zimbra',
                     '--password={}'.format(store_mysql_conn['password']),
                     db,
                     '--tables', table,
                     '--where={}'.format(where),
                     '--no-create-db',
                     '--skip-triggers',
                     '--compact',
                     '--no-create-info',
                     '--extended-insert=FALSE',
                     '--default-character-set=utf8mb4',
                     '>',
                     tmp_file]

    mysqldump_cmd2 = ' '.join(map(str, mysqldump_cmd))
    bash_filename = f"{TMP_PATH}dump_sql_{db}_{table}_{user.zimbraId}.sh"
    bash_file = open(f"{bash_filename}", 'w')
    bash_file.write(f"#!/bin/bash\n{mysqldump_cmd2}\n")
    bash_file.close()

    result = subprocess.run(['chmod', '777', f'{bash_filename}'])
    result = subprocess.run(
        [f"{bash_filename}"],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    logger.debug(f"[MYSQL_DUMP] - {mysqldump_cmd2} result output = {result.stdout}")
    logger.debug(f"[MYSQL_DUMP] - {mysqldump_cmd2}  error = {result.stderr}")

    return open(tmp_file)


def inject_dump(store_mysql_conn, db, table, data_dump, user):
    logger.debug(f"[MYSQL_INJECT] - {db}  start injecting")

    mysql_cmd = ['/opt/zimbra/bin/mysql', '--host=127.0.0.1',
                 '-P', store_mysql_conn['port'],
                 '-u', 'zimbra',
                 '--password={}'.format(store_mysql_conn['password']),
                 '--default-character-set=utf8mb4',
                 db,
                 '<',
                 data_dump]

    mysql_cmd2 = f"/opt/zimbra/bin/mysql --host=127.0.0.1 -P {store_mysql_conn['port']} -u zimbra " \
                 f"--password={store_mysql_conn['password']} --default-character-set=utf8mb4 {db}" \
                 f" < {data_dump}"

    bash_filename = f"{TMP_PATH}inject_sql_{db}_{table}_{user.zimbraId}.sh"
    bash_file = open(f"{bash_filename}", 'w')
    bash_file.write(f"#!/bin/bash\n{mysql_cmd2}\n")
    bash_file.close()
    sleep(10)

    result = subprocess.run(['chmod', '777', f'{bash_filename}'])
    result = subprocess.run(
        [f"{bash_filename}"],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    logger.debug(f"[MYSQL_INJECT] - {mysql_cmd2} result output = {result.stdout}")
    if len(result.stderr) > 0:
        logger.debug(f"[MYSQL_INJECT] - {mysql_cmd2} error = {result.stderr}")
    return True


def alter_and_write_mid_gid(store_db_info, db, data, user):
    if is_mailbox_id_exists(store_db_info, user.new_mailbox_id):
        logger.info(f"[ALTER_AND_WRITE_MID_GID][{user.email}][{user.mailbox_id}] - mailbox_id {user.new_mailbox_id} "
                    f"present in {user.new_zimbraMailHost}")
        return False
    logger.info(
        f"[ALTER_AND_WRITE_MID_GID][{user.email}][{user.mailbox_id}] - mailbox_id {user.new_mailbox_id} OK no present "
        f"in {user.new_zimbraMailHost}")
    # read the output line by line
    for line in data:
        # modify the output here, for example, replace all occurrences of "old_value" with "new_value"
        modified_line = line.replace(f'({user.mailbox_id},{user.mailbox_group}',
                                     f'({user.new_mailbox_id},{user.mailbox_group}')
        # write the modified output to a file
        logger.debug(f"[ALTER_AND_WRITE_MID_GID][{user.email}][{user.mailbox_id}] modified_line = {modified_line}")
        connect_and_push(store_db_info, db, modified_line, False)
    return True


def alter_and_write_mid(store_db_info, db, data, user, table):
    if not is_mailbox_id_exists(store_db_info, user.new_mailbox_id):
        logger.info(
            f"[ALTER_AND_WRITE_MID][{db}][{table}][{user.email}][{user.mailbox_id}] - mailbox_id {user.new_mailbox_id} "
            f" NOT present in {user.new_zimbraMailHost}")
        return False
    logger.info(
        f"[ALTER_AND_WRITE_MID][{db}][{table}][{user.email}][{user.mailbox_id}] - mailbox_id {user.new_mailbox_id} OK  present "
        f"in {user.new_zimbraMailHost}")
    # read the output line by line
    modified_line = str()
    tmp_line = str
    tmp_file = f'{TMP_PATH}{user.zimbraId}.{table}.sql'
    for line in data:
        # modify the output here, for example, replace all occurrences of "old_value" with "new_value"
        tmp_line = line.replace(f'({user.mailbox_id},',
                                f'({user.new_mailbox_id},')
        modified_line += tmp_line
    tmp_file_fd = open(tmp_file, 'w')
    tmp_file_fd.write(modified_line)
    tmp_file_fd.close()

    # rsync(user.zimbraMailHost, {TMP_PATH}, user.new_zimbraMailHost,{TMP_PATH}, user)
    logger.info("Waiting for disk writing file")

    if get_count_db(all_stores[user.zimbraMailHost], f'mboxgroup{user.mailbox_group}', table, user.mailbox_id) > 0:
        sleep(3)
        if inject_dump(all_stores[user.new_zimbraMailHost], db, table, tmp_file, user):
            return True
        else:
            return False
    logger.info(f"[ALTER_AND_WRITE_MID][{db}][{table}][{user.email}][{user.mailbox_id}] - Empty Table continue..")
    return True


def flush_all_memcached():
    for proxy in get_all_proxy_servers():
        if not flush_memcached(proxy):
            return False
    return True


class User:
    def __init__(self, email):
        self.email = email
        self.zimbraMailHost = ''
        self.zimbraId = ''
        self.mailbox_id = ''
        self.mailbox_group = ''
        self.new_mailbox_id = ''
        self.new_zimbraMailHost = ''
        self.pre_sync = False
        self.push_db = False
        self.store_folder = ''
        self.new_store_folder = ''
        self.index_folder = ''
        self.new_index_folder = ''
        self.new_mailbox_id_affected = False
        self.table_new_mailbox_id_started = False
        self.table_import_started = False

    def init(self, new_mailHost):
        self.new_zimbraMailHost = new_mailHost
        if not self.set_ldap_data():
            return False

        if not self.validate_location():
            logger.error(f"[{self.email}] - Wrong location of store please run script"
                         f" on {self.zimbraMailHost} instead of {get_zmhostname()}")
            return False

        self.set_db_data()
        self.set_new_mailbox_id()
        self.create_dest_folders()
        self.presync()
        return True

    def move(self):
        start_time = time.time()
        if self.final_sync():
            end_time = time.time()
            time_diff = end_time - start_time
            logger.info(f"[{self.email}] - Moved from "
                        f"{self.zimbraMailHost} to {self.new_zimbraMailHost}"
                        f" in {time_diff} seconds")
        else:
            logger.error(f"[{self.email}] - Failed To move from "
                         f"{self.zimbraMailHost} to {self.new_zimbraMailHost}")

    def set_ldap_data(self):
        self.zimbraId = get_zimbraId(self.email)
        if self.zimbraId is None:
            return False
        self.zimbraMailHost = get_ZimbraMailHost(self.email)
        if self.zimbraMailHost is None:
            return False
        return True

    def set_db_data(self):
        self.mailbox_id = get_mailbox_id(all_stores[self.zimbraMailHost], self.email)
        if (int(self.mailbox_id) % 100) == 0:
            self.mailbox_group = '100'
        else:
            self.mailbox_group = str(int(self.mailbox_id) % 100)

    def set_new_mailbox_id(self):
        new_mailbox_id = str(OFFSET_MAILBOX_ID + int(self.mailbox_id))
        local_offset = 0
        while is_mailbox_id_exists(all_stores[self.new_zimbraMailHost], new_mailbox_id):
            new_mailbox_id = str(OFFSET_MAILBOX_ID + local_offset + int(self.mailbox_id))
            local_offset += 1000
        self.new_mailbox_id = new_mailbox_id
        self.new_mailbox_id_affected = True

    def validate_location(self):
        if str(get_zmhostname()).strip() == self.zimbraMailHost.strip():
            return True
        return False

    def activate_maintenance(self):
        modify_account(self.zimbraId, zimbraAccountStatus='maintenance')
        sleep(3)

    def disable_maintenance(self):
        modify_account(self.zimbraId, zimbraAccountStatus='active')

    def modify_zimbraMailHost(self):
        return modify_account(self.zimbraId, zimbraMailHost=self.new_zimbraMailHost)

    def modify_transportmap(self):
        return modify_account(self.zimbraId, zimbraMailTransport='lmtp:' + self.new_zimbraMailHost + ':7025')

    def create_dest_folders(self):
        shift_id = str(int(self.new_mailbox_id) >> 12)
        self.new_store_folder = '/opt/zimbra/store/{}/{}/'.format(shift_id, self.new_mailbox_id)
        self.new_index_folder = '/opt/zimbra/index/{}/{}/'.format(shift_id, self.new_mailbox_id)
        create_remote_folder(self.new_zimbraMailHost, self.new_store_folder)
        create_remote_folder(self.new_zimbraMailHost, self.new_index_folder)

    def presync(self):
        shift_id = str(int(self.mailbox_id) >> 12)
        self.store_folder = '/opt/zimbra/store/{}/{}/'.format(shift_id, self.mailbox_id)
        self.index_folder = '/opt/zimbra/index/{}/{}/'.format(shift_id, self.mailbox_id)
        rsync(self.zimbraMailHost, self.store_folder, self.new_zimbraMailHost, self.new_store_folder, self)
        rsync(self.zimbraMailHost, self.index_folder, self.new_zimbraMailHost, self.new_index_folder, self)

    def sync_db(self):
        zimbra_table = get_dump(all_stores[self.zimbraMailHost], 'zimbra', 'mailbox', 'id={}'.format(self.mailbox_id),
                                self)
        if alter_and_write_mid_gid(all_stores[self.new_zimbraMailHost], 'zimbra', zimbra_table, self):
            self.table_new_mailbox_id_started = True
        else:
            return False
        for table in ALL_MAILBOX_TABLES:
            entries = get_dump(all_stores[self.zimbraMailHost],
                               f'mboxgroup{self.mailbox_group}',
                               table,
                               f'mailbox_id={self.mailbox_id}',
                               self)
            if not alter_and_write_mid(all_stores[self.new_zimbraMailHost],
                                       f'mboxgroup{self.mailbox_group}',
                                       entries,
                                       self,
                                       table):
                return False
            self.table_import_started = True
        return validate_db_migration(self)

    def final_sync(self):
        self.activate_maintenance()
        self.presync()
        if self.sync_db():
            self.modify_zimbraMailHost()
            self.modify_transportmap()
            flush_cache_all_stores()
            if flush_all_memcached():
                self.disable_maintenance()
                return True
            else:
                logger.info(f"[{self.email}] - account under maintenance still please flushcache and active with :"
                            f"zmprov ma {self.email} zimbraAccountStatus active")
                return False
        else:
            rollback_on_db(self)
        self.disable_maintenance()
        return False


def get_count_db(info, db, table, mailbox_id):
    return connect_and_get(info, db, f"select count(*) from {table} where mailbox_id={mailbox_id}")[0]['count(*)']


def validate_db_migration(user):
    for table in ALL_MAILBOX_TABLES:
        if get_count_db(all_stores[user.zimbraMailHost],
                        f'mboxgroup{user.mailbox_group}',
                        table,
                        user.mailbox_id) != get_count_db(all_stores[user.new_zimbraMailHost],
                                                         f'mboxgroup{user.mailbox_group}',
                                                         table,
                                                         user.new_mailbox_id):
            logger.info(f"[DB-VALIDATION][{user.email}] - integrity error on {table}")
            sleep(30)
            return False
    return True


def validate_ssh_tunnel():
    for store_name, info in all_stores.items():
        port = int(info['port'])
        logger.info(f"[MYSQL_TUNNEL] - validating port listen on {port} for store {store_name}...")
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        result = sock.connect_ex(('127.0.0.1', port))
        sock.close()
        if result == 0:
            logger.info(f"[MYSQL_TUNNEL][{store_name}] - validating port listen on {port} --> [OK]")
        else:
            logger.error(f"[MYSQL_TUNNEL][{store_name}] - validating port listen on {port} --> [NOK]...")
            return False
    return True


def create_all_ssh_tunnel():
    for store_name, info in all_stores.items():
        create_ssh_tunnel(store_name,
                          local_port=info['port'])
        sleep(3)


def disable_f_key_check():
    for store_name, info in all_stores.items():
        connect_and_push(info, 'zimbra', "SET GLOBAL FOREIGN_KEY_CHECKS=0", False)


def rollback_on_db(user):
    logger.info(f"[ROLLING-BACK][{user.email}] - removing db entries started")
    connect_and_push(all_stores[user.new_zimbraMailHost],
                     'zimbra',
                     f'delete from mailbox where id={user.new_mailbox_id}', False)
    for table in ALL_MAILBOX_TABLES:
        connect_and_push(all_stores[user.new_zimbraMailHost],
                         f'mboxgroup{user.mailbox_group}',
                         f"delete from {table} where mailbox_id={user.new_mailbox_id}", False)

    logger.info(f"[ROLLING-BACK][{user.email}] - removing db entries finished")


def validate_requirements():
    return flush_all_memcached() and flush_cache_all_stores() and validate_ssh_tunnel()


def move_user(user, destination, args):
    if validate_requirements():
        logger.info("[VALIDATION] - All requirements validated")
        disable_f_key_check()
        if args.separate_log:
            file_handler_user = RotatingFileHandler(LOG_PATH + user + ".log", 'a', 100000000, 100)
            file_handler_user.setLevel(getLogLevel('DEBUG'))
            file_handler_user.setFormatter(formatter)
            logger.addHandler(file_handler_user)

        user = User(user)
        if user.init(destination):
            user.move()
        else:
            logger.error(f'[USER-VALIDATION]- Unable to init user {user.email} for migration please check error lines')
    else:
        logger.info("[VALIDATION] - All requirements are not validated exiting...")


def start():
    parser = argparse.ArgumentParser(description=' Fast mailbox move')

    parser.add_argument("-a", "--email", help="define email addr to move", required=False)
    parser.add_argument("-d", "--destination", help="define destination store", required=False)
    parser.add_argument("-f", "--csv-file", help="define csv file", required=False)
    parser.add_argument("-l", "--listen", help="active tunneling mode", required=False, action='store_true')
    parser.add_argument("-s", "--separate-log", help="separate logs  per user", required=False, action='store_true')
    args = parser.parse_args()

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    if args.listen:
        create_all_ssh_tunnel()

    if (args.email is None and args.csv_file is None) or args.destination is None:
        parser.print_help()
        sys.exit(1)

    if args.email is None:
        csv_fd = open(args.csv_file)
        for user in csv_fd.readlines():
            move_user(user.strip().lower(), args.destination, args)

    else:
        move_user(args.email, args.destination, args)

    if args.csv_file is None:
        sys.exit(1)


if __name__ == '__main__':
    start()
