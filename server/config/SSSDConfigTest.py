'''
Created on Sep 18, 2009

@author: sgallagh
'''
import unittest

import SSSDConfig

class SSSDConfigTestValid(unittest.TestCase):
    def setUp(self):
        pass

    def tearDown(self):
        pass

    def testServices(self):
        sssdconfig = SSSDConfig.SSSDConfig("etc/sssd.api.conf",
                                "etc/sssd.api.d")
        sssdconfig.import_config("testconfigs/sssd-valid.conf")

        # Validate services
        services = sssdconfig.list_services()
        self.assertTrue('sssd' in services)
        self.assertTrue('nss' in services)
        self.assertTrue('pam' in services)
        self.assertTrue('dp' in services)

        #Verify service attributes
        sssd_service = sssdconfig.get_service('sssd')
        service_opts = sssd_service.list_options()

        self.assertTrue('config_file_version' in service_opts.keys())
        self.assertEquals(sssd_service.get_option('config_file_version'), 2)

        self.assertTrue('services' in service_opts.keys())
        service_list = sssd_service.get_option('services')
        self.assertTrue('nss' in service_list)
        self.assertTrue('pam' in service_list)

        self.assertTrue('domains' in service_opts)

        self.assertTrue('reconnection_retries' in service_opts)

        del sssdconfig
        sssdconfig = SSSDConfig.SSSDConfig("etc/sssd.api.conf",
                                     "etc/sssd.api.d")
        sssdconfig.new_config()
        sssdconfig.delete_service('sssd')
        new_sssd_service = sssdconfig.new_service('sssd');
        new_options = new_sssd_service.list_options();

        self.assertTrue('debug_level' in new_options)
        self.assertEquals(new_options['debug_level'][0], int)

        self.assertTrue('command' in new_options)
        self.assertEquals(new_options['command'][0], str)

        self.assertTrue('reconnection_retries' in new_options)
        self.assertEquals(new_options['reconnection_retries'][0], int)

        self.assertTrue('config_file_version' in new_options)
        self.assertEquals(new_options['config_file_version'][0], int)

        self.assertTrue('services' in new_options)
        self.assertEquals(new_options['debug_level'][0], int)

        self.assertTrue('domains' in new_options)
        self.assertEquals(new_options['domains'][0], list)
        self.assertEquals(new_options['domains'][1], str)

        self.assertTrue('sbus_timeout' in new_options)
        self.assertEquals(new_options['sbus_timeout'][0], int)

        self.assertTrue('re_expression' in new_options)
        self.assertEquals(new_options['re_expression'][0], str)

        self.assertTrue('full_name_format' in new_options)
        self.assertEquals(new_options['full_name_format'][0], str)

        del sssdconfig
        pass

    def testDomains(self):
        sssdconfig = SSSDConfig.SSSDConfig("etc/sssd.api.conf",
                                "etc/sssd.api.d")
        sssdconfig.import_config("testconfigs/sssd-valid.conf")

        #Validate domain list
        domains = sssdconfig.list_domains()
        self.assertTrue('LOCAL' in domains)
        self.assertTrue('LDAP' in domains)
        self.assertTrue('PROXY' in domains)
        self.assertTrue('IPA' in domains)

        #Verify domain attributes
        ipa_domain = sssdconfig.get_domain('IPA')
        domain_opts = ipa_domain.list_options()
        self.assertTrue('debug_level' in domain_opts.keys())
        self.assertTrue('id_provider' in domain_opts.keys())
        self.assertTrue('auth_provider' in domain_opts.keys())

        del sssdconfig
        pass

    def testListProviders(self):
        sssdconfig = SSSDConfig.SSSDConfig("etc/sssd.api.conf",
                                "etc/sssd.api.d")

        sssdconfig.new_config()
        junk_domain = sssdconfig.new_domain('junk')
        providers = junk_domain.list_providers()
        self.assertTrue('ldap' in providers.keys())

    def testCreateNewLocalConfig(self):
        sssdconfig = SSSDConfig.SSSDConfig("etc/sssd.api.conf",
                                "etc/sssd.api.d")

        sssdconfig.new_config()

        local_domain = sssdconfig.new_domain('LOCAL')
        local_domain.add_provider('local', 'id')
        local_domain.set_option('debug_level', 1)
        local_domain.set_option('default_shell', '/bin/tcsh')
        local_domain.set_active(True)
        sssdconfig.save_domain(local_domain)

        sssdconfig.write('/tmp/testCreateNewLocalConfig.conf')

    def testCreateNewLDAPConfig(self):
        sssdconfig = SSSDConfig.SSSDConfig("etc/sssd.api.conf",
                                "etc/sssd.api.d")

        sssdconfig.new_config()

        ldap_domain = sssdconfig.new_domain('LDAP')
        ldap_domain.add_provider('ldap', 'id')
        ldap_domain.set_option('debug_level', 1)
        ldap_domain.set_active(True)
        sssdconfig.save_domain(ldap_domain)

        sssdconfig.write('/tmp/testCreateNewLDAPConfig.conf')

    def testModifyExistingConfig(self):
        sssdconfig = SSSDConfig.SSSDConfig("etc/sssd.api.conf",
                                "etc/sssd.api.d")
        sssdconfig.import_config("testconfigs/sssd-valid.conf")

        ldap_domain = sssdconfig.get_domain('LDAP')
        ldap_domain.set_option('debug_level', 3)

        ldap_domain.remove_provider('ldap', 'auth')
        ldap_domain.add_provider('krb5', 'auth')
        ldap_domain.set_active(True)
        sssdconfig.save_domain(ldap_domain)

        sssdconfig.write('/tmp/testModifyExistingConfig.conf')

class SSSDConfigTestSSSDService(unittest.TestCase):
    def setUp(self):
        self.schema = SSSDConfig.SSSDConfigSchema("etc/sssd.api.conf",
                                                  "etc/sssd.api.d")
        pass

    def tearDown(self):
        pass

    def testInit(self):
        # Positive test
        service = SSSDConfig.SSSDService('sssd', self.schema)

        # Type Error test
        # Name is not a string
        try:
            service = SSSDConfig.SSSDService(3, self.schema)
        except TypeError:
            pass
        else:
            self.fail("Expected TypeError exception")

        # TypeError test
        # schema is not an SSSDSchema
        try:
            service = SSSDConfig.SSSDService('3', self)
        except TypeError:
            pass
        else:
            self.fail("Expected TypeError exception")

        # ServiceNotRecognizedError test
        try:
            service = SSSDConfig.SSSDService('ssd', self.schema)
        except SSSDConfig.ServiceNotRecognizedError:
            pass
        else:
            self.fail("Expected ServiceNotRecognizedError")


    def testListOptions(self):
        service = SSSDConfig.SSSDService('sssd', self.schema)

        options = service.list_options()
        control_list = [
            'config_file_version',
            'services',
            'domains',
            'sbus_timeout',
            're_expression',
            'full_name_format',
            'debug_level',
            'command',
            'reconnection_retries']

        self.assertTrue(type(options) == dict,
                        "Options should be a dictionary")

        # Ensure that all of the expected defaults are there
        for option in control_list:
            self.assertTrue(option in options.keys(),
                            "Option [%s] missing" %
                            option)

        # Ensure that there aren't any unexpected options listed
        for option in options.keys():
            self.assertTrue(option in control_list,
                            'Option [%s] unexpectedly found' %
                            option)

        self.assertTrue(type(options['config_file_version']) == tuple,
                        "Option values should be a tuple")

        self.assertTrue(options['config_file_version'][0] == int,
                        "config_file_version should require an int. " +
                        "list_options is requiring a %s" %
                        options['config_file_version'][0])

        self.assertTrue(options['config_file_version'][1] == None,
                        "config_file_version should not require a subtype. " +
                        "list_options is requiring a %s" %
                        options['config_file_version'][1])

        self.assertTrue(options['config_file_version'][0] == int,
                        "config_file_version should default to 2. " +
                        "list_options specifies %d" %
                        options['config_file_version'][2])

        self.assertTrue(type(options['services']) == tuple,
                        "Option values should be a tuple")

        self.assertTrue(options['services'][0] == list,
                        "services should require an list. " +
                        "list_options is requiring a %s" %
                        options['services'][0])

        self.assertTrue(options['services'][1] == str,
                        "services should require a subtype of str. " +
                        "list_options is requiring a %s" %
                        options['services'][1])

    def testSetOption(self):
        service = SSSDConfig.SSSDService('sssd', self.schema)

        # Positive test - Exactly right
        service.set_option('debug_level', 2)
        self.assertEqual(service.get_option('debug_level'), 2)

        # Positive test - Allow converting "safe" values
        service.set_option('debug_level', '2')
        self.assertEqual(service.get_option('debug_level'), 2)

        # Positive test - Remove option if value is None
        service.set_option('debug_level', None)
        self.assertTrue('debug_level' not in service.options.keys())

        # Negative test - Nonexistent Option
        try:
            service.set_option('nosuchoption', 1)
        except SSSDConfig.NoOptionError:
            pass
        else:
            self.fail("Expected NoOptionError")

        # Negative test - Incorrect type
        try:
            service.set_option('debug_level', 'two')
        except TypeError:
            pass
        else:
            self.fail("Expected TypeError")

    def testGetOption(self):
        service = SSSDConfig.SSSDService('sssd', self.schema)

        # Positive test - Single-valued
        self.assertEqual(service.get_option('config_file_version'), 2)

        # Positive test - List of values
        self.assertEqual(service.get_option('services'), ['nss', 'pam'])

        # Negative Test - Bad Option
        try:
            service.get_option('nosuchoption')
        except SSSDConfig.NoOptionError:
            pass
        else:
            self.fail("Expected NoOptionError")

    def testGetAllOptions(self):
        service = SSSDConfig.SSSDService('sssd', self.schema)

        #Positive test
        options = service.get_all_options()
        control_list = [
            'config_file_version',
            'services',
            'sbus_timeout',
            're_expression',
            'full_name_format',
            'debug_level',
            'reconnection_retries']

        self.assertTrue(type(options) == dict,
                        "Options should be a dictionary")

        # Ensure that all of the expected defaults are there
        for option in control_list:
            self.assertTrue(option in options.keys(),
                            "Option [%s] missing" %
                            option)

        # Ensure that there aren't any unexpected options listed
        for option in options.keys():
            self.assertTrue(option in control_list,
                            'Option [%s] unexpectedly found' %
                            option)

    def testRemoveOption(self):
        service = SSSDConfig.SSSDService('sssd', self.schema)

        # Positive test - Remove an option that exists
        self.assertEqual(service.get_option('debug_level'), 0)
        service.remove_option('debug_level')
        try:
            service.get_option('debug_level')
        except SSSDConfig.NoOptionError:
            pass
        else:
            self.fail("debug_level should have been removed")

        # Positive test - Remove an option that doesn't exist
        try:
            service.get_option('nosuchentry')
        except SSSDConfig.NoOptionError:
            pass
        else:
            self.fail("nosuchentry should not exist")

        service.remove_option('nosuchentry')

class SSSDConfigTestSSSDDomain(unittest.TestCase):
    def setUp(self):
        self.schema = SSSDConfig.SSSDConfigSchema("etc/sssd.api.conf",
                                                  "etc/sssd.api.d")
        pass

    def tearDown(self):
        pass

    def testInit(self):
        # Positive Test
        domain = SSSDConfig.SSSDDomain('mydomain', self.schema)

        # Negative Test - Name not a string
        try:
            domain = SSSDConfig.SSSDDomain(2, self.schema)
        except TypeError:
            pass
        else:
            self.fail("Expected TypeError")

        # Negative Test - Schema is not an SSSDSchema
        try:
            domain = SSSDConfig.SSSDDomain('mydomain', self)
        except TypeError:
            pass
        else:
            self.fail("Expected TypeError")

    def testGetName(self):
        # Positive Test
        domain = SSSDConfig.SSSDDomain('mydomain', self.schema)

        self.assertEqual(domain.get_name(), 'mydomain')

    def testSetActive(self):
        #Positive Test
        domain = SSSDConfig.SSSDDomain('mydomain', self.schema)

        # Should default to inactive
        self.assertFalse(domain.active)
        domain.set_active(True)
        self.assertTrue(domain.active)
        domain.set_active(False)
        self.assertFalse(domain.active)

    def testListOptions(self):
        domain = SSSDConfig.SSSDDomain('sssd', self.schema)

        # First test default options
        options = domain.list_options()
        control_list = [
            'debug_level',
            'min_id',
            'max_id',
            'timeout',
            'magic_private_groups',
            'enumerate',
            'cache_credentials',
            'use_fully_qualified_names',
            'id_provider',
            'auth_provider',
            'access_provider',
            'chpass_provider']

        self.assertTrue(type(options) == dict,
                        "Options should be a dictionary")

        # Ensure that all of the expected defaults are there
        for option in control_list:
            self.assertTrue(option in options.keys(),
                            "Option [%s] missing" %
                            option)

        # Ensure that there aren't any unexpected options listed
        for option in options.keys():
            self.assertTrue(option in control_list,
                            'Option [%s] unexpectedly found' %
                            option)

        self.assertTrue(type(options['max_id']) == tuple,
                        "Option values should be a tuple")

        self.assertTrue(options['max_id'][0] == int,
                        "config_file_version should require an int. " +
                        "list_options is requiring a %s" %
                        options['max_id'][0])

        self.assertTrue(options['max_id'][1] == None,
                        "config_file_version should not require a subtype. " +
                        "list_options is requiring a %s" %
                        options['max_id'][1])

        # Add a provider and verify that the new options appear
        domain.add_provider('local', 'id')
        control_list.extend(
            ['default_shell',
             'base_directory'])

        options = domain.list_options()

        self.assertTrue(type(options) == dict,
                        "Options should be a dictionary")

        # Ensure that all of the expected defaults are there
        for option in control_list:
            self.assertTrue(option in options.keys(),
                            "Option [%s] missing" %
                            option)

        # Ensure that there aren't any unexpected options listed
        for option in options.keys():
            self.assertTrue(option in control_list,
                            'Option [%s] unexpectedly found' %
                            option)

        # Add a provider that has global options and verify that
        # The new options appear.
        domain.add_provider('krb5', 'auth')

        backup_list = control_list[:]
        control_list.extend(
            ['krb5_kdcip',
             'krb5_realm',
             'krb5_ccachedir',
             'krb5_ccname_template',
             'krb5_auth_timeout'])

        options = domain.list_options()

        self.assertTrue(type(options) == dict,
                        "Options should be a dictionary")

        # Ensure that all of the expected defaults are there
        for option in control_list:
            self.assertTrue(option in options.keys(),
                            "Option [%s] missing" %
                            option)

        # Ensure that there aren't any unexpected options listed
        for option in options.keys():
            self.assertTrue(option in control_list,
                            'Option [%s] unexpectedly found' %
                            option)

        # Remove the auth domain and verify that the options
        # revert to the backup_list
        domain.remove_provider('krb5', 'auth')
        options = domain.list_options()

        self.assertTrue(type(options) == dict,
                        "Options should be a dictionary")

        # Ensure that all of the expected defaults are there
        for option in backup_list:
            self.assertTrue(option in options.keys(),
                            "Option [%s] missing" %
                            option)

        # Ensure that there aren't any unexpected options listed
        for option in options.keys():
            self.assertTrue(option in backup_list,
                            'Option [%s] unexpectedly found' %
                            option)

    def testListProviders(self):
        domain = SSSDConfig.SSSDDomain('sssd', self.schema)

        control_provider_dict = {
            'krb5': ('auth', 'access', 'chpass'),
            'local': ('auth', 'chpass', 'access', 'id'),
            'ldap': ('id', 'auth')}

        providers = domain.list_providers()

        self.assertEqual(providers, control_provider_dict)

    def testListProviderOptions(self):
        domain = SSSDConfig.SSSDDomain('sssd', self.schema)

        # Test looking up a specific provider type
        options = domain.list_provider_options('krb5', 'auth')
        control_list = [
            'krb5_kdcip',
            'krb5_realm',
            'krb5_ccachedir',
            'krb5_ccname_template',
            'krb5_auth_timeout']

        self.assertTrue(type(options) == dict,
                        "Options should be a dictionary")

        # Ensure that all of the expected defaults are there
        for option in control_list:
            self.assertTrue(option in options.keys(),
                            "Option [%s] missing" %
                            option)

        # Ensure that there aren't any unexpected options listed
        for option in options.keys():
            self.assertTrue(option in control_list,
                            'Option [%s] unexpectedly found' %
                            option)

        #Test looking up all provider values
        options = domain.list_provider_options('krb5')
        control_list.extend(['krb5_changepw_principal'])

        self.assertTrue(type(options) == dict,
                        "Options should be a dictionary")

        # Ensure that all of the expected defaults are there
        for option in control_list:
            self.assertTrue(option in options.keys(),
                            "Option [%s] missing" %
                            option)

        # Ensure that there aren't any unexpected options listed
        for option in options.keys():
            self.assertTrue(option in control_list,
                            'Option [%s] unexpectedly found' %
                            option)

    def testAddProvider(self):
        domain = SSSDConfig.SSSDDomain('sssd', self.schema)

        # Positive Test
        domain.add_provider('local', 'id')

        # Negative Test - No such backend type
        try:
            domain.add_provider('nosuchbackend', 'auth')
        except SSSDConfig.NoSuchProviderError:
            pass
        else:
            self.fail("Expected NoSuchProviderError")

        # Negative Test - No such backend subtype
        try:
            domain.add_provider('ldap', 'nosuchsubtype')
        except SSSDConfig.NoSuchProviderSubtypeError:
            pass
        else:
            self.fail("Expected NoSuchProviderSubtypeError")

        # Negative Test - Try to add a second provider of the same type
        try:
            domain.add_provider('ldap', 'id')
        except SSSDConfig.ProviderSubtypeInUse:
            pass
        else:
            self.fail("Expected ProviderSubtypeInUse")

    def testRemoveProvider(self):
        domain = SSSDConfig.SSSDDomain('sssd', self.schema)

        # First test default options
        options = domain.list_options()
        control_list = [
            'debug_level',
            'min_id',
            'max_id',
            'timeout',
            'magic_private_groups',
            'enumerate',
            'cache_credentials',
            'use_fully_qualified_names',
            'id_provider',
            'auth_provider',
            'access_provider',
            'chpass_provider']

        self.assertTrue(type(options) == dict,
                        "Options should be a dictionary")

        # Ensure that all of the expected defaults are there
        for option in control_list:
            self.assertTrue(option in options.keys(),
                            "Option [%s] missing" %
                            option)

        # Ensure that there aren't any unexpected options listed
        for option in options.keys():
            self.assertTrue(option in control_list,
                            'Option [%s] unexpectedly found' %
                            option)

        self.assertTrue(type(options['max_id']) == tuple,
                        "Option values should be a tuple")

        self.assertTrue(options['max_id'][0] == int,
                        "config_file_version should require an int. " +
                        "list_options is requiring a %s" %
                        options['max_id'][0])

        self.assertTrue(options['max_id'][1] == None,
                        "config_file_version should not require a subtype. " +
                        "list_options is requiring a %s" %
                        options['max_id'][1])

        # Add a provider and verify that the new options appear
        domain.add_provider('local', 'id')
        control_list.extend(
            ['default_shell',
             'base_directory'])

        options = domain.list_options()

        self.assertTrue(type(options) == dict,
                        "Options should be a dictionary")

        # Ensure that all of the expected defaults are there
        for option in control_list:
            self.assertTrue(option in options.keys(),
                            "Option [%s] missing" %
                            option)

        # Ensure that there aren't any unexpected options listed
        for option in options.keys():
            self.assertTrue(option in control_list,
                            'Option [%s] unexpectedly found' %
                            option)

        # Add a provider that has global options and verify that
        # The new options appear.
        domain.add_provider('krb5', 'auth')

        backup_list = control_list[:]
        control_list.extend(
            ['krb5_kdcip',
             'krb5_realm',
             'krb5_ccachedir',
             'krb5_ccname_template',
             'krb5_auth_timeout'])

        options = domain.list_options()

        self.assertTrue(type(options) == dict,
                        "Options should be a dictionary")

        # Ensure that all of the expected defaults are there
        for option in control_list:
            self.assertTrue(option in options.keys(),
                            "Option [%s] missing" %
                            option)

        # Ensure that there aren't any unexpected options listed
        for option in options.keys():
            self.assertTrue(option in control_list,
                            'Option [%s] unexpectedly found' %
                            option)

        # Remove the auth domain and verify that the options
        # revert to the backup_list
        domain.remove_provider('krb5', 'auth')
        options = domain.list_options()

        self.assertTrue(type(options) == dict,
                        "Options should be a dictionary")

        # Ensure that all of the expected defaults are there
        for option in backup_list:
            self.assertTrue(option in options.keys(),
                            "Option [%s] missing" %
                            option)

        # Ensure that there aren't any unexpected options listed
        for option in options.keys():
            self.assertTrue(option in backup_list,
                            'Option [%s] unexpectedly found' %
                            option)

        # Test removing nonexistent provider - Real
        domain.remove_provider('ldap', 'id')

        # Test removing nonexistent provider - Bad backend type
        # Should pass without complaint
        domain.remove_provider('nosuchbackend', 'id')

        # Test removing nonexistent provider - Bad provider type
        # Should pass without complaint
        domain.remove_provider('ldap', 'nosuchprovider')

    def testGetOption(self):
        domain = SSSDConfig.SSSDDomain('sssd', self.schema)

        # Positive Test - Ensure that we can get a valid option
        self.assertEqual(domain.get_option('debug_level'), 0)

        # Negative Test - Try to get valid option that is not set
        try:
            domain.get_option('max_id')
        except SSSDConfig.NoOptionError:
            pass
        else:
            self.fail("Expected NoOptionError")

        # Positive Test - Set the above option and get it
        domain.set_option('max_id', 10000)
        self.assertEqual(domain.get_option('max_id'), 10000)

        # Negative Test - Try yo get invalid option
        try:
            domain.get_option('nosuchoption')
        except SSSDConfig.NoOptionError:
            pass
        else:
            self.fail("Expected NoOptionError")

    def testSetOption(self):
        domain = SSSDConfig.SSSDDomain('sssd', self.schema)

        # Positive Test
        domain.set_option('max_id', 10000)
        self.assertEqual(domain.get_option('max_id'), 10000)

        # Positive Test - Remove option if value is None
        domain.set_option('max_id', None)
        self.assertTrue('max_id' not in domain.get_all_options().keys())

        # Negative Test - invalid option
        try:
            domain.set_option('nosuchoption', 1)
        except SSSDConfig.NoOptionError:
            pass
        else:
            self.fail("Expected NoOptionError")

        # Negative Test - incorrect type
        try:
            domain.set_option('max_id', 'a string')
        except TypeError:
            pass
        else:
            self.fail("Expected TypeError")

        # Positive Test - Coax options to appropriate type
        domain.set_option('max_id', '10000')
        self.assertEqual(domain.get_option('max_id'), 10000)

        domain.set_option('max_id', 30.2)
        self.assertEqual(domain.get_option('max_id'), 30)

    def testRemoveOption(self):
        domain = SSSDConfig.SSSDDomain('sssd', self.schema)

        # Positive test - Remove existing option
        self.assertTrue('min_id' in domain.get_all_options().keys())
        domain.remove_option('min_id')
        self.assertFalse('min_id' in domain.get_all_options().keys())

        # Positive test - Remove unset but valid option
        self.assertFalse('max_id' in domain.get_all_options().keys())
        domain.remove_option('max_id')
        self.assertFalse('max_id' in domain.get_all_options().keys())

        # Positive test - Remove unset and unknown option
        self.assertFalse('nosuchoption' in domain.get_all_options().keys())
        domain.remove_option('nosuchoption')
        self.assertFalse('nosuchoption' in domain.get_all_options().keys())

class SSSDConfigTestSSSDConfig(unittest.TestCase):
    def setUp(self):
        pass

    def tearDown(self):
        pass

    def testInit(self):
        # Positive test
        sssdconfig = SSSDConfig.SSSDConfig("etc/sssd.api.conf",
                                           "etc/sssd.api.d")

        # Negative Test - No Such File
        try:
            sssdconfig = SSSDConfig.SSSDConfig("nosuchfile.api.conf",
                                               "etc/sssd.api.d")
        except IOError:
            pass
        else:
            self.fail("Expected IOError")

        # Negative Test - Schema is not parsable
        try:
            sssdconfig = SSSDConfig.SSSDConfig("testconfigs/noparse.api.conf",
                                               "etc/sssd.api.d")
        except SSSDConfig.ParsingError:
            pass
        else:
            self.fail("Expected ParsingError")

    def testImportConfig(self):
        # Positive Test
        sssdconfig = SSSDConfig.SSSDConfig("etc/sssd.api.conf",
                                           "etc/sssd.api.d")
        sssdconfig.import_config("testconfigs/sssd-valid.conf")

        # Verify that all sections were imported
        control_list = [
            'sssd',
            'nss',
            'pam',
            'dp',
            'domain/PROXY',
            'domain/IPA',
            'domain/LOCAL',
            'domain/LDAP',
            ]

        for section in control_list:
            self.assertTrue(sssdconfig.has_section(section),
                            "Section [%s] missing" %
                            section)
        for section in sssdconfig.sections():
            self.assertTrue(section in control_list)

        # Verify that all options were imported for a section
        control_list = [
            'services',
            'reconnection_retries',
            'domains',
            'config_file_version']

        for option in control_list:
            self.assertTrue(sssdconfig.has_option('sssd', option),
                            "Option [%s] missing from [sssd]" %
                            option)
        for option in sssdconfig.options('sssd'):
            self.assertTrue(option in control_list,
                            "Option [%s] unexpectedly found" %
                            option)

        #TODO: Check the types and values of the settings

        # Negative Test - Missing config file
        try:
            sssdconfig = SSSDConfig.SSSDConfig("etc/sssd.api.conf",
                                               "etc/sssd.api.d")
            sssdconfig.import_config("nosuchfile.conf")
        except IOError:
            pass
        else:
            self.fail("Expected IOError")

        # Negative Test - Invalid config file
        try:
            sssdconfig = SSSDConfig.SSSDConfig("etc/sssd.api.conf",
                                               "etc/sssd.api.d")
            sssdconfig.import_config("testconfigs/sssd-invalid.conf")
        except SSSDConfig.ParsingError:
            pass
        else:
            self.fail("Expected ParsingError")

        # Negative Test - Already initialized
        sssdconfig = SSSDConfig.SSSDConfig("etc/sssd.api.conf",
                                           "etc/sssd.api.d")
        sssdconfig.import_config("testconfigs/sssd-valid.conf")
        try:
            sssdconfig.import_config("testconfigs/sssd-valid.conf")
        except SSSDConfig.AlreadyInitializedError:
            pass
        else:
            self.fail("Expected AlreadyInitializedError")

    def testNewConfig(self):
        # Positive Test
        sssdconfig = SSSDConfig.SSSDConfig("etc/sssd.api.conf",
                                           "etc/sssd.api.d")
        sssdconfig.new_config()

        # Check that the defaults were set
        control_list = [
            'sssd',
            'nss',
            'pam']
        for section in control_list:
            self.assertTrue(sssdconfig.has_section(section),
                            "Section [%s] missing" %
                            section)
        for section in sssdconfig.sections():
            self.assertTrue(section in control_list)

        control_list = [
            'config_file_version',
            'services',
            'sbus_timeout',
            're_expression',
            'full_name_format',
            'debug_level',
            'reconnection_retries']
        for option in control_list:
            self.assertTrue(sssdconfig.has_option('sssd', option),
                            "Option [%s] missing from [sssd]" %
                            option)
        for option in sssdconfig.options('sssd'):
            self.assertTrue(option in control_list,
                            "Option [%s] unexpectedly found" %
                            option)

        # Negative Test - Already Initialized
        try:
            sssdconfig.new_config()
        except SSSDConfig.AlreadyInitializedError:
            pass
        else:
            self.fail("Expected AlreadyInitializedError")

    def testWrite(self):
        #TODO Write tests to compare output files
        pass

    def testListServices(self):
        sssdconfig = SSSDConfig.SSSDConfig("etc/sssd.api.conf",
                                           "etc/sssd.api.d")

        # Negative Test - sssdconfig not initialized
        try:
            sssdconfig.list_services()
        except SSSDConfig.NotInitializedError:
            pass
        else:
            self.fail("Expected NotInitializedError")

        sssdconfig.new_config()

        control_list = [
            'sssd',
            'pam',
            'nss']
        service_list = sssdconfig.list_services()
        for service in control_list:
            self.assertTrue(service in service_list,
                            "Service [%s] missing" %
                            service)
        for service in service_list:
            self.assertTrue(service in control_list,
                            "Service [%s] unexpectedly found" %
                            service)

    def testGetService(self):
        sssdconfig = SSSDConfig.SSSDConfig("etc/sssd.api.conf",
                                           "etc/sssd.api.d")

        # Negative Test - Not initialized
        try:
            service = sssdconfig.get_service('sssd')
        except SSSDConfig.NotInitializedError:
            pass
        else:
            self.fail("Expected NotInitializedError")

        sssdconfig.new_config()

        service = sssdconfig.get_service('sssd')
        self.assertTrue(isinstance(service, SSSDConfig.SSSDService))

        # TODO verify the contents of this service

        # Negative Test - No such service
        try:
            service = sssdconfig.get_service('nosuchservice')
        except SSSDConfig.NoServiceError:
            pass
        else:
            self.fail("Expected NoServiceError")

    def testNewService(self):
        sssdconfig = SSSDConfig.SSSDConfig("etc/sssd.api.conf",
                                           "etc/sssd.api.d")

        # Negative Test - Not initialized
        try:
            service = sssdconfig.new_service('sssd')
        except SSSDConfig.NotInitializedError:
            pass
        else:
            self.fail("Expected NotInitializedError")

        sssdconfig.new_config()

        # Positive Test
        # First need to remove the existing service
        sssdconfig.delete_service('sssd')
        service = sssdconfig.new_service('sssd')
        self.failUnless(service.get_name() in sssdconfig.list_services())

        # TODO: check that the values of this new service
        # are set to the defaults from the schema

    def testDeleteService(self):
        sssdconfig = SSSDConfig.SSSDConfig("etc/sssd.api.conf",
                                           "etc/sssd.api.d")

        # Negative Test - Not initialized
        try:
            service = sssdconfig.delete_service('sssd')
        except SSSDConfig.NotInitializedError:
            pass
        else:
            self.fail("Expected NotInitializedError")

        sssdconfig.new_config()

        # Positive Test
        service = sssdconfig.delete_service('sssd')

    def testSaveService(self):
        sssdconfig = SSSDConfig.SSSDConfig("etc/sssd.api.conf",
                                           "etc/sssd.api.d")

        new_service = SSSDConfig.SSSDService('sssd', sssdconfig.schema)

        # Negative Test - Not initialized
        try:
            service = sssdconfig.save_service(new_service)
        except SSSDConfig.NotInitializedError:
            pass
        else:
            self.fail("Expected NotInitializedError")

        # Positive Test
        sssdconfig.new_config()
        sssdconfig.save_service(new_service)

        # TODO: check that all entries were saved correctly (change a few)

        # Negative Test - Type Error
        try:
            sssdconfig.save_service(self)
        except TypeError:
            pass
        else:
            self.fail("Expected TypeError")

    def testListActiveDomains(self):
        sssdconfig = SSSDConfig.SSSDConfig("etc/sssd.api.conf",
                                           "etc/sssd.api.d")

        # Negative Test - Not Initialized
        try:
            sssdconfig.list_active_domains()
        except SSSDConfig.NotInitializedError:
            pass
        else:
            self.fail("Expected NotInitializedError")

        # Positive Test
        sssdconfig.import_config('testconfigs/sssd-valid.conf')

        control_list = [
            'IPA',
            'LOCAL']
        active_domains = sssdconfig.list_active_domains()

        for domain in control_list:
            self.assertTrue(domain in active_domains,
                            "Domain [%s] missing" %
                            domain)
        for domain in active_domains:
            self.assertTrue(domain in control_list,
                            "Domain [%s] unexpectedly found" %
                            domain)

    def testListInactiveDomains(self):
        sssdconfig = SSSDConfig.SSSDConfig("etc/sssd.api.conf",
                                           "etc/sssd.api.d")

        # Negative Test - Not Initialized
        try:
            sssdconfig.list_inactive_domains()
        except SSSDConfig.NotInitializedError:
            pass
        else:
            self.fail("Expected NotInitializedError")

        # Positive Test
        sssdconfig.import_config('testconfigs/sssd-valid.conf')

        control_list = [
            'PROXY',
            'LDAP']
        inactive_domains = sssdconfig.list_inactive_domains()

        for domain in control_list:
            self.assertTrue(domain in inactive_domains,
                            "Domain [%s] missing" %
                            domain)
        for domain in inactive_domains:
            self.assertTrue(domain in control_list,
                            "Domain [%s] unexpectedly found" %
                            domain)

    def testListDomains(self):
        sssdconfig = SSSDConfig.SSSDConfig("etc/sssd.api.conf",
                                           "etc/sssd.api.d")

        # Negative Test - Not Initialized
        try:
            sssdconfig.list_domains()
        except SSSDConfig.NotInitializedError:
            pass
        else:
            self.fail("Expected NotInitializedError")

        # Positive Test
        sssdconfig.import_config('testconfigs/sssd-valid.conf')

        control_list = [
            'IPA',
            'LOCAL',
            'PROXY',
            'LDAP']
        domains = sssdconfig.list_domains()

        for domain in control_list:
            self.assertTrue(domain in domains,
                            "Domain [%s] missing" %
                            domain)
        for domain in domains:
            self.assertTrue(domain in control_list,
                            "Domain [%s] unexpectedly found" %
                            domain)

    def testGetDomain(self):
        sssdconfig = SSSDConfig.SSSDConfig("etc/sssd.api.conf",
                                           "etc/sssd.api.d")

        # Negative Test - Not initialized
        try:
            domain = sssdconfig.get_domain('sssd')
        except SSSDConfig.NotInitializedError:
            pass
        else:
            self.fail("Expected NotInitializedError")

        sssdconfig.import_config('testconfigs/sssd-valid.conf')

        domain = sssdconfig.get_domain('IPA')
        self.assertTrue(isinstance(domain, SSSDConfig.SSSDDomain))

        # TODO verify the contents of this domain

        # Negative Test - No such domain
        try:
            domain = sssdconfig.get_domain('nosuchdomain')
        except SSSDConfig.NoDomainError:
            pass
        else:
            self.fail("Expected NoDomainError")

    def testNewDomain(self):
        sssdconfig = SSSDConfig.SSSDConfig("etc/sssd.api.conf",
                                           "etc/sssd.api.d")

        # Negative Test - Not initialized
        try:
            domain = sssdconfig.new_domain('example.com')
        except SSSDConfig.NotInitializedError:
            pass
        else:
            self.fail("Expected NotInitializedError")

        sssdconfig.new_config()

        # Positive Test
        domain = sssdconfig.new_domain('example.com')
        self.assertTrue(isinstance(domain, SSSDConfig.SSSDDomain))
        self.failUnless(domain.get_name() in sssdconfig.list_domains())
        self.failUnless(domain.get_name() in sssdconfig.list_inactive_domains())

        # TODO: check that the values of this new domain
        # are set to the defaults from the schema

    def testDeleteDomain(self):
        sssdconfig = SSSDConfig.SSSDConfig("etc/sssd.api.conf",
                                           "etc/sssd.api.d")

        # Negative Test - Not initialized
        try:
            sssdconfig.delete_domain('IPA')
        except SSSDConfig.NotInitializedError:
            pass
        else:
            self.fail("Expected NotInitializedError")

        # Positive Test
        sssdconfig.import_config('testconfigs/sssd-valid.conf')

        self.assertTrue('IPA' in sssdconfig.list_domains())
        self.assertTrue('IPA' in sssdconfig.list_active_domains())
        sssdconfig.delete_domain('IPA')
        self.assertFalse('IPA' in sssdconfig.list_domains())
        self.assertFalse('IPA' in sssdconfig.list_active_domains())

    def testSaveDomain(self):
        sssdconfig = SSSDConfig.SSSDConfig("etc/sssd.api.conf",
                                           "etc/sssd.api.d")
        # Negative Test - Not initialized
        try:
            sssdconfig.delete_domain('IPA')
        except SSSDConfig.NotInitializedError:
            pass
        else:
            self.fail("Expected NotInitializedError")

        # Positive Test
        sssdconfig.new_config()
        domain = sssdconfig.new_domain('example.com')
        domain.add_provider('ldap', 'id')
        domain.set_option('ldap_uri', 'ldap://ldap.example.com')
        domain.set_active(True)
        sssdconfig.save_domain(domain)

        self.assertTrue('example.com' in sssdconfig.list_domains())
        self.assertTrue('example.com' in sssdconfig.list_active_domains())
        self.assertEqual(sssdconfig.get('domain/example.com', 'ldap_uri'),
                         'ldap://ldap.example.com')

        # Negative Test - Type Error
        try:
            sssdconfig.save_service(self)
        except TypeError:
            pass
        else:
            self.fail("Expected TypeError")

if __name__ == "__main__":
    error = 0

    suite = unittest.TestLoader().loadTestsFromTestCase(SSSDConfigTestSSSDService)
    res = unittest.TextTestRunner(verbosity=99).run(suite)
    if not res.wasSuccessful():
        error |= 0x1

    suite = unittest.TestLoader().loadTestsFromTestCase(SSSDConfigTestSSSDDomain)
    res = unittest.TextTestRunner(verbosity=99).run(suite)
    if not res.wasSuccessful():
        error |= 0x2

    suite = unittest.TestLoader().loadTestsFromTestCase(SSSDConfigTestSSSDConfig)
    res = unittest.TextTestRunner(verbosity=99).run(suite)
    if not res.wasSuccessful():
        error |= 0x4

    suite = unittest.TestLoader().loadTestsFromTestCase(SSSDConfigTestValid)
    res = unittest.TextTestRunner(verbosity=99).run(suite)
    if not res.wasSuccessful():
        error |= 0x8

    exit(error)