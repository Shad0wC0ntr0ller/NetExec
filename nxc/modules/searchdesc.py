import os
from impacket.ldap import ldap, ldapasn1
from impacket.smbconnection import SMBConnection

class NXCModule:
    """
    Retrieve and search descriptions for all users, printing matching results with username, description, and account status
    Module by : @shad0wcntr0ller
    """
    name = 'searchdesc'
    description = 'Retrieve and search descriptions for all users, printing matching results with username, description, and account status'
    supported_protocols = ['ldap']
    opsec_safe = True
    multiple_hosts = False

    def options(self, context, module_options):
        """
        Add options to the module.
        """
        self.keywords = [keyword.strip() for keyword in module_options.get('SEARCH', '').split(',') if keyword.strip()]

    def on_login(self, context, connection):
        try:
            # Initialize connection to LDAP
            context.log.info(f"Connecting to LDAP server at ldap://{connection.host}")

            if connection.kerberos:
                ldap_connection = ldap.LDAPConnection(f'ldap://{connection.host}', connection.baseDN, None)
                ldap_connection.kerberosLogin(connection.username, connection.password, connection.domain, lmhash=connection.lmhash, nthash=connection.nthash, aesKey=connection.aesKey, kdcHost=connection.kdcHost)
            else:
                ldap_connection = ldap.LDAPConnection(f'ldap://{connection.host}', connection.baseDN, None)
                ldap_connection.login(connection.username, connection.password, connection.domain, lmhash=connection.lmhash, nthash=connection.nthash)

            # Define the search filter for all user accounts
            search_filter = '(objectClass=user)'
            attributes = ['sAMAccountName', 'description', 'userAccountControl']

            context.log.info(f'Using search filter: {search_filter}')
            context.log.info(f'Attributes to retrieve: {attributes}')

            # Default keywords if none are provided
            keywords = self.keywords if self.keywords else ['PW', 'PASS', 'ADMIN']
            users = []

            try:
                # Use paged search to retrieve all user accounts
                paged_search_control = ldapasn1.SimplePagedResultsControl(criticality=True, size=1000)
                search_results = ldap_connection.search(searchFilter=search_filter, attributes=attributes, searchControls=[paged_search_control])

                for item in search_results:
                    if isinstance(item, ldapasn1.SearchResultEntry):
                        context.log.debug(f'Raw item: {item.prettyPrint()}')

                        sam_account_name = None
                        description = None
                        user_account_control = None

                        for attribute in item['attributes']:
                            context.log.debug(f'Attribute: {attribute.prettyPrint()}')
                            if str(attribute['type']) == 'sAMAccountName':
                                sam_account_name = str(attribute['vals'][0])
                            elif str(attribute['type']) == 'description':
                                description = str(attribute['vals'][0])
                            elif str(attribute['type']) == 'userAccountControl':
                                user_account_control = str(attribute['vals'][0])

                        context.log.debug(f"Processing user: {sam_account_name}, Description: {description}, UAC: {user_account_control}")

                        if sam_account_name and user_account_control is not None:
                            account_status = 'disabled' if int(user_account_control) & 2 else 'enabled'
                            if description and any(keyword.lower() in description.lower() for keyword in keywords):
                                if not any(sam_account_name in user for user in users):
                                    users.append((sam_account_name, description, account_status))
                                    context.log.debug(f'Added user: {sam_account_name}, {description}, {account_status}')

                # Print the results
                if users:
                    for user in users:
                        context.log.highlight(f'{user[0]}: {user[1]} : {user[2]}')
                    context.log.success(f'Found {len(users)} users with matching descriptions.')
                else:
                    context.log.info(f'No users found with matching descriptions.')

            except Exception as e:
                context.log.fail(f'Error occurred during search: {e}')

            ldap_connection.close()
            return True

        except Exception as e:
            context.log.fail(f'Error occurred during LDAP connection: {e}')
            return False

