import subprocess
from enum import Enum


class Role(Enum):
    ServerAdministrator = 'ServerAdministrator'
    SiteAdministratorCreator = 'SiteAdministratorCreator'
    SiteAdministratorExplorer = 'SiteAdministratorExplorer'
    Creator = 'Creator'
    ExplorerCanPublish = 'ExplorerCanPublish'
    Explorer = 'Explorer'
    Viewer = 'Viewer'
    ReadOnly = 'ReadOnly'
    Unlicensed = 'Unlicensed'


class ServerSetting(Enum):
    AllowScheduling = 'allow_scheduling'
    EmbeddedCredentials = 'embedded_credentials'
    RememberPasswordsForever = 'remember_passwords_forever'


class SiteStatus(Enum):
    Active = 'active'
    Suspended = 'suspended'


class PDFPageSize(Enum):
    Unspecified = 'unspecified'
    Letter = 'letter'
    Legal = 'legal'
    Note = 'note'
    Folio = 'folio'
    Tabloid = 'tabloid'
    Ledger = 'ledger'
    Statement = 'statement'
    Executive = 'executive'
    A3 = 'a3'
    A4 = 'a4'
    A5 = 'a5'
    B4 = 'b4'
    B5 = 'b5'
    Quarto = 'quarto'


class PDFPageLayout(Enum):
    Landscape = 'landscape'
    Portrait = 'portrait'


class ExportFormat(Enum):
    # Formats for views:
    PDF = '--pdf'
    PNG = '--png'
    CSV = '--csv'
    # Formats for workbook:
    FULL_PDF = '--fullpdf'


class SourceType(Enum):
    Workbook = '--workbook'
    Datasource = '--datasource'
    URL = '--url'


class PyTabCMD(object):
    def __init__(self, tabcmd_path):
        self.tabcmd = tabcmd_path

    def _add_global_options(self, command, **kwargs):
        server = kwargs.get('server', None)
        user = kwargs.get('user', None)
        password = kwargs.get('password', None)
        use_certificate = kwargs.get('use_certificate', None)
        password_file_path = kwargs.get('password_file_path', None)
        site = kwargs.get('site', None)
        proxy = kwargs.get('proxy', None)
        no_prompt = kwargs.get('no_prompt', None)
        no_certcheck = kwargs.get('no_certcheck', False)
        no_cookie = kwargs.get('no_cookie', False)
        timeout = kwargs.get('timeout', None)

        global_commands = [
            '--server' if server is not None else '',
            server if server is not None else '',
            '--user' if user is not None else '',
            "\"%s\"" % user if user is not None else '',
            '--password' if password is not None else '',
            "\"%s\"" % password if password is not None else '',
            '--use-certificate' if use_certificate is not None else '',
            '--password-file' if password_file_path is not None else '',
            "\"%s\"" % password_file_path if password_file_path is not None else '',
            '--site' if site is not None else '',
            site if site is not None else '',
            '--proxy' if proxy is not None else '--no-proxy',
            proxy if proxy is not None else '',
            '--no-certcheck' if no_certcheck else '',
            '--no-prompt' if no_prompt else '',
            '--no-cookie' if no_cookie else '--cookie',
            '--timeout' if timeout is not None else '',
            timeout if timeout is not None else ''
        ]
        command = command.extend(global_commands)
        return command

    def _execute_command_call(self, command, **kwargs):
        command = self._add_global_options(command, **kwargs)
        return subprocess.check_call(list(filter(lambda a: a != '', command)))

    def _execute_command_output(self, command, **kwargs):
        command = self._add_global_options(command, **kwargs)
        return subprocess.check_output(list(filter(lambda a: a != '', command)))

    def addusers(self, group, users, complete=True, **kwargs):
        """
        https://onlinehelp.tableau.com/current/server/en-us/tabcmd_cmd.htm#id1999d76f-638e-47d4-86ac-fe8e206ed364
        :return:
        """
        command = [
            self.tabcmd,
            'addusers', "\"%s\"" % group,
            '--users', "\"%s\"" % users,
            '--complete' if complete else '--no-complete'
        ]
        return self._execute_command_call(command, **kwargs)

    def creategroup(self, name, **kwargs):
        """
        Creates a group. Use addusers (for local groups)
        and syncgroup (for Active Directory groups) commands to add users after the group has been created.
        https://onlinehelp.tableau.com/current/server/en-us/tabcmd_cmd.htm#idbfa546df-2be7-444f-8bb8-07978b127783
        :return:
        """
        command = [
            self.tabcmd,
            'creategroup',
            "\"%s\"" % name
        ]
        return self._execute_command_call(command, **kwargs)

    def createproject(self, name, description, **kwargs):
        """
        Creates a project.
        Using tabcmd, you can specify only a top-level project in a project hierarchy.
        To automate tasks you want to perform on a project within a parent project,
        use the equivalent Tableau REST API call.
        https://onlinehelp.tableau.com/current/server/en-us/tabcmd_cmd.htm#id5a3316ed-45bb-4da4-b557-58492b2d4ac8
        :return:
        """
        command = [
            self.tabcmd,
            'createproject',
            '-n', "\"%s\"" % name,
            '-d', '\"%s\"' % description
        ]
        return self._execute_command_call(command, **kwargs)

    def createsite(self, site_name, url=None, user_quota=None, storage_quota=None, site_mode=True, **kwargs):
        """
        Creates a site.
        https://onlinehelp.tableau.com/current/server/en-us/tabcmd_cmd.htm#id6f434e96-89d1-4aa2-a935-4c22fa1e2506
        :param site_name: Name of the site
        :param url: Used in URLs to specify the site. Different from the site name
        :param user_quota: Maximum number of users that can be added to the site
        :param storage_quota: In MB, the amount of workbooks, extracts, and data sources that can be stored on the site
        :param site_mode: Allows or denies site administrators the ability to add users to or remove users from the site
        :return:
        """
        command = [
            self.tabcmd,
            'createsite',
            "\"%s\"" % site_name,
            '-url' if url is not None else '', "\"%s\"" % url if url is not None else '',
            '--user-quota' if user_quota is not None else '', "%s" % user_quota if user_quota is not None else '',
            '--storage-quota' if storage_quota is not None else '',
            "%s" % storage_quota if storage_quota is not None else '',
            '--site-mode' if site_mode else '--no-site-mode'
        ]
        return self._execute_command_call(command, **kwargs)

    def createsiteusers(self, file_path, role=Role.Viewer, complete=True, nowait=False, silent_progress=True, **kwargs):
        """
        Adds users to a site, based on information supplied in a comma-separated values (CSV) file.
        If the user is not already created on the server, the command creates the user before adding
        that user to the site.
        https://onlinehelp.tableau.com/current/server/en-us/tabcmd_cmd.htm#idd1b7729f-dd20-475a-96f6-17fcd2577894
        :return:
        """
        command = [
            self.tabcmd,
            'createsiteusers',
            "\"%s\"" % file_path,
            '--role', "\"%s\"" % role.value,
            '--complete' if complete else '--no-complete',
            '--nowait' if nowait else '',
            '--silent-progress' if silent_progress else ''
        ]
        return self._execute_command_output(command, **kwargs)

    def createusers(self, file_path, role=Role.Viewer, complete=True, nowait=False, silent_progress=True, **kwargs):
        """
        https://onlinehelp.tableau.com/current/server/en-us/tabcmd_cmd.htm#ide42a948a-cd9c-4b73-9ef2-3a58eda2d095
        :return:
        """
        command = [
            self.tabcmd,
            'createusers',
            "\"%s\"" % file_path,
            '--role', "\"%s\"" % role.value,
            '--complete' if complete else '--no-complete',
            '--nowait' if nowait else '',
            '--silent-progress' if silent_progress else ''
        ]
        return self._execute_command_output(command, **kwargs)

    def delete(self, source_name, source_type=SourceType.Workbook, project=None, **kwargs):
        """
        Deletes the specified workbook or datasource
        This command takes the name of the workbook or datasource as it is on the server,
        not the file name when it was published.
        https://onlinehelp.tableau.com/current/server/en-us/tabcmd_cmd.htm#idfdf59712-84ed-4590-9471-541d316917a6
        :param source_name: name of the workbook or datasource
        :param source_type: type (workbook or datasource)
        :param project: The name of the project containing the workbook you want to delete.
        If not specified, the “Default” project is assumed.
        :return:
        """
        if source_type == SourceType.Workbook:
            command = [
                self.tabcmd,
                'initialuser',
                source_type.value, "\"%s\"" % source_name,
                '--r' if project is not None else '', '\"%s\"' % project if project is not None else ''
            ]
            return self._execute_command_call(command, **kwargs)
        elif source_type == SourceType.Datasource:
            command = [
                self.tabcmd,
                'initialuser',
                source_type.value, "\"%s\"" % source_name,
                '--r' if project is not None else '', '\"%s\"' % project if project is not None else ''
            ]
            return self._execute_command_call(command, **kwargs)
        else:
            # TODO: throw an error
            return False

    def deletegroup(self, group_name, **kwargs):
        """
        https://onlinehelp.tableau.com/current/server/en-us/tabcmd_cmd.htm#id0d009916-bee3-4ef0-a6ac-22188c0e7f30
        :return:
        """
        command = [
            self.tabcmd,
            'deletegroup', "\"%s\"" % group_name
        ]
        return self._execute_command_call(command, **kwargs)

    def deleteproject(self, project_name, **kwargs):
        """
        https://onlinehelp.tableau.com/current/server/en-us/tabcmd_cmd.htm#idfdf59712-84ed-4590-9471-541d316917a6
        :return:
        """
        command = [
            self.tabcmd,
            'deleteproject', "\"%s\"" % project_name
        ]
        return self._execute_command_call(command, **kwargs)

    def deletesite(self, site_name, **kwargs):
        """
        https://onlinehelp.tableau.com/current/server/en-us/tabcmd_cmd.htm#id54a7f404-5d1b-452e-8273-0ab8396da641
        :return:
        """
        command = [
            self.tabcmd,
            'deletesite', "\"%s\"" % site_name
        ]
        return self._execute_command_call(command, **kwargs)

    def deletesiteusers(self, site_users_path, **kwargs):
        """
        https://onlinehelp.tableau.com/current/server/en-us/tabcmd_cmd.htm#deletesiteusers
        :return:
        """
        command = [
            self.tabcmd,
            'deletesiteusers', "\"%s\"" % site_users_path
        ]
        return self._execute_command_call(command, **kwargs)

    def deleteusers(self, users_path, complete=True, **kwargs):
        """
        https://onlinehelp.tableau.com/current/server/en-us/tabcmd_cmd.htm#id6a8ef3d6-d17b-4c31-be47-7b09437eeec0
        :return:
        """
        command = [
            self.tabcmd,
            'deletesiteusers', "\"%s\"" % users_path,
            '--complete' if complete else '--no-complete'
        ]
        return self._execute_command_call(command, **kwargs)

    def editdomain(self, domain_id, domain_name, domain_nickname, **kwargs):
        """
        https://onlinehelp.tableau.com/current/server/en-us/tabcmd_cmd.htm#editdomain
        :return:
        """
        command = [
            self.tabcmd,
            'editdomain',
            '--id', "%s" % domain_id,
            '--name', "\"s\"" % domain_name,
            '--nickname', "\"s\"" % domain_nickname
        ]
        return self._execute_command_call(command, **kwargs)

    def editsite(self, current_site_id, new_site_name=None, new_site_id=None,
                 user_quota=None, site_mode=True, status=SiteStatus.Active, storage_quota=None, **kwargs):
        """
        https://onlinehelp.tableau.com/current/server/en-us/tabcmd_cmd.htm#id06d8e2e0-d7a1-4733-b0df-d1e02f66919b
        :return:
        """
        if new_site_name is not None or \
                new_site_id is not None or \
                user_quota is not None or \
                storage_quota is not None:
            command = [
                self.tabcmd,
                'editsite', "%s" % current_site_id,
                '--site-name' if new_site_name is not None else '',
                '\"%s\"' % new_site_name if new_site_name is not None else '',
                '--site-id' if new_site_id is not None else '',
                '\"%s\"' % new_site_id if new_site_id is not None else '',
                '--user-quota' if user_quota is not None else '',
                '%s' % user_quota if user_quota is not None else '',
                '--site-mode' if site_mode is not None else '--no-site-mode',
                '--status', "%s" % status.value,
                '--storage-quota' if storage_quota is not None else '',
                '%s' % storage_quota if storage_quota is not None else ''
            ]
            return self._execute_command_call(command, **kwargs)
        else:
            # TODO: Need throw an error
            return False

    def export(self, workbook_view_name, file_path=None, file_format=ExportFormat.PNG,
               page_layout: PDFPageLayout = None, page_size: PDFPageSize = None,
               width=None, height=None, **kwargs):
        """
        https://onlinehelp.tableau.com/current/server/en-us/tabcmd_cmd.htm#id7cb8d032-a4ff-43da-9990-15bdfe64bcd0
        :return:
        """
        if file_format == ExportFormat.FULL_PDF or file_format == ExportFormat.PDF:
            command = [
                self.tabcmd,
                'export', '\"%s\"' % workbook_view_name,
                file_format.value,
                '--pagelayout' if page_layout is not None else '',
                page_layout.value if page_layout is not None else '',
                '--pagesize' if page_size is not None else '',
                page_size.value if page_size is not None else '',
                '--width' if width is not None else '',
                '%s' % width if width is not None else '',
                '--height' if height is not None else '',
                '%s' % height if height is not None else '',
                '--filename' if file_path is not None else '',
                '\"%s\"' % file_path if file_path is not None else ''
            ]
            return self._execute_command_call(command, **kwargs)
        else:
            command = [
                self.tabcmd,
                'export', '\"%s\"' % workbook_view_name,
                file_format.value,
                '--filename' if file_path is not None else '',
                '\"%s\"' % file_path if file_path is not None else ''
            ]
            return self._execute_command_call(command, **kwargs)

    def get(self, url, file_path=None, **kwargs):
        """
        https://onlinehelp.tableau.com/current/server/en-us/tabcmd_cmd.htm#id7e0a0627-ad89-4135-a1c2-85b1d8472568
        :return:
        """
        command = [
            self.tabcmd,
            'get', '\"%s\"' % url,
            '--filename' if file_path is not None else '',
            '\"%s\"' % file_path if file_path is not None else ''
        ]
        return self._execute_command_call(command, **kwargs)

    def initialuser(self, username, password, server, friendly=None, **kwargs):
        """
        Create the initial administrative user on a server that does not have an initial administrative user defined.
        Note: The tabcmd initialuser command does not require authentication to Tableau Server,
        but you must run the command on the initial server node.
        https://onlinehelp.tableau.com/current/server/en-us/tabcmd_cmd.htm#initialuser
        :param username: user
        :param password: password for user
        :param server: server link
        :param friendly: creates the initial administrative user with the display name
        :return:
        """
        command = [
            self.tabcmd,
            'initialuser',
            '--friendly' if friendly is not None else '', '\"%s\"' % friendly if friendly is not None else ''
        ]
        kwargs['server'] = server
        kwargs['username'] = username
        kwargs['password'] = password
        return self._execute_command_call(command, **kwargs)

    def listdomains(self, **kwargs):
        """
        Displays a list of the Active Directory domains that are in use on the server,
        along with their nicknames and IDs.
        If the server is configured to use local authentication, the command returns only the domain name local.

        https://onlinehelp.tableau.com/current/server/en-us/tabcmd_cmd.htm#listdomains

        :return: string
        """
        command = [
            self.tabcmd,
            'listdomains'
        ]
        return self._execute_command_output(command, **kwargs)

    def listsites(self, username, password, **kwargs):
        """
        Returns a list of sites to which the logged in user belongs.
        https://onlinehelp.tableau.com/current/server/en-us/tabcmd_cmd.htm#idc7467cb6-6cef-49bf-9358-a3e4addd5fa0
        :param username
        :param password
        :return: string
        """
        command = [
            self.tabcmd,
            'listsites'
        ]
        kwargs['username'] = username
        kwargs['password'] = password
        return self._execute_command_output(command, **kwargs)

    def login(self, server, username, password, site=None, **kwargs):
        """
        Logs in a Tableau Server user.
        https://onlinehelp.tableau.com/current/server/en-us/tabcmd_cmd.htm#id5fba51c9-5608-4520-8ceb-2caf4846a2be
        :return:
        """
        command = [
            self.tabcmd,
            'login'
        ]
        kwargs['server'] = server
        kwargs['username'] = username
        kwargs['password'] = password
        kwargs['site'] = site
        return self._execute_command_call(command, **kwargs)

    def logout(self, **kwargs):
        """
        Logs out of the server
        https://onlinehelp.tableau.com/current/server/en-us/tabcmd_cmd.htm#id8f512aec-57a4-4ed4-94c4-86e91ea9cc9c
        :return: 0 if correct command, otherwise raise CalledProcessError
        """
        command = [
            self.tabcmd,
            'logout'
        ]
        return self._execute_command_call(command, **kwargs)

    def publish(self, source_path, publish_name=None, project=None, overwrite=True,
                db_username=None, db_password=None, save_db_password=False,
                oauth_username=None, save_oauth=False, thumbnail_username=None, thumbnail_group=None,
                tabbed=False, append=False, replace=False, disable_uploader=False, restart=False, **kwargs):
        """
        https://onlinehelp.tableau.com/current/server/en-us/tabcmd_cmd.htm#iddf805b62-18ff-4497-9245-adc6905b2084
        :return:
        """
        command = [
            self.tabcmd,
            'publish', '\"%s\"' % source_path,
            '--name' if publish_name is not None else '', '\"%s\"' % publish_name if publish_name is not None else '',
            '--project' if project is not None else '', '\"%s\"' % project if project is not None else '',
            '--overwrite' if overwrite else '',
            '--db-username' if db_username is not None else '',
            '\"%s\"' % db_username if db_username is not None else '',
            '--db-password' if db_password is not None else '',
            '\"%s\"' % db_password if db_password is not None else '',
            '--save-db-password' if save_db_password else '',
            '--oauth-username' if oauth_username is not None else '',
            '\"%s\"' % oauth_username if oauth_username is not None else '',
            '--save-oauth' if save_oauth else '',
            '--thumbnail-username' if thumbnail_username is not None else '',
            '\"%s\"' % thumbnail_username if thumbnail_username is not None else '',
            '--thumbnail-group' if thumbnail_group is not None else '',
            '\"%s\"' % thumbnail_group if thumbnail_group is not None else '',
            '--tabbed' if tabbed else '',
            '--append' if append else '',
            '--replace' if replace else '',
            '--disable-uploader' if disable_uploader else '',
            '--restart' if restart else ''
        ]
        return self._execute_command_call(command, **kwargs)

    def publishsamples(self, project_name, **kwargs):
        """
        https://onlinehelp.tableau.com/current/server/en-us/tabcmd_cmd.htm#publishsamples
        :return:
        """
        command = [
            self.tabcmd,
            'publishsamples',
            '--name', '\"%s\"' % project_name
        ]
        return self._execute_command_call(command, **kwargs)

    def refreshextracts(self, source_name, source_type=SourceType.Workbook, project=None, incremental=False,
                        synchronous=False, add_calculations=False, remove_calculations=False, **kwargs):
        """
        https://onlinehelp.tableau.com/current/server/en-us/tabcmd_cmd.htm#id4cdb3410-1c41-4dad-b1d2-306542ac9b32
        :return:
        """
        command = [
            self.tabcmd,
            'refreshextracts',
            source_type.value, '\"%s\"' % source_name,
            '--project' if project is not None else '', '\"%s\"' % project if project is not None else '',
            '--incremental' if incremental else '',
            '--synchronous' if synchronous else '',
            '--addcalculations' if add_calculations else '',
            '--removecalculations' if remove_calculations else ''
        ]
        return self._execute_command_call(command, **kwargs)

    def removeusers(self, group_name, users_file_path=None, complete=True, **kwargs):
        """
        https://onlinehelp.tableau.com/current/server/en-us/tabcmd_cmd.htm#id5cc30cba-44b8-48b0-93d6-5707938d157a
        :return:
        """
        command = [
            self.tabcmd,
            'removeusers', "\"%s\"" % group_name,
            '--user' if users_file_path is not None else '',
            "\"%s\"" % users_file_path if users_file_path is not None else '',
            '--complete' if complete else '--no-complete'
        ]
        return self._execute_command_output(command, **kwargs)

    def runschedule(self, schedule_name, **kwargs):
        """
        https://onlinehelp.tableau.com/current/server/en-us/tabcmd_cmd.htm#idd9d99c44-c9be-4191-9191-402341775a3d
        :return:
        """
        command = [
            self.tabcmd,
            'runschedule', "\"%s\"" % schedule_name
        ]
        return self._execute_command_call(command, **kwargs)

    def set(self, setting=ServerSetting.EmbeddedCredentials, **kwargs):
        """
        https://onlinehelp.tableau.com/current/server/en-us/tabcmd_cmd.htm#idfe12acaf-ed64-4f0c-8eb8-b83c9de12382
        :return:
        """
        command = [
            self.tabcmd,
            'set', "%s" % setting.value
        ]
        return self._execute_command_call(command, **kwargs)

    def syncgroup(self, group_name, role=Role.Unlicensed, overwrite_site_role=False, silent_progress=False, **kwargs):
        """
        https://onlinehelp.tableau.com/current/server/en-us/tabcmd_cmd.htm#ide6a39f29-77ff-44f6-b946-c2b56b31a2f9
        :return:
        """
        command = [
            self.tabcmd,
            'syncgroup', "\"%s\"" % group_name,
            '--role' if role is not None else '', "\"%s\"" % role.value if role is not None else '',
            '--silent-progress' if silent_progress else '',
            '--overwritesiterole' if overwrite_site_role else ''
        ]
        return self._execute_command_output(command, **kwargs)

    def version(self, **kwargs):
        """
        Displays the version information for the current installation of the tabcmd utility
        https://onlinehelp.tableau.com/current/server/en-us/tabcmd_cmd.htm#id825f5d18-529c-408a-b876-57693195bbdd
        :return: string
        """
        command = [
            self.tabcmd,
            'version'
        ]
        return self._execute_command_output(command, **kwargs)
