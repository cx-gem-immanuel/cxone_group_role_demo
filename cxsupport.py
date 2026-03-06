from datetime import datetime, timedelta
from email import header  
import requests
import json  
import time
import re
from logsupport import setup_logger  

logger = setup_logger()

class CheckmarxClient:
    def __init__(self, iam_host, ast_host, tenant, api_key, is_verbose=False):
        """
        Initialize the client with the specified IAM host, AST host, tenant, and API key.

        Args:
            iam_host (str): The IAM (Identity and Access Management) service host URL.
            ast_host (str): The AST (Application Security Testing) service host URL.
            tenant (str): The tenant identifier.
            api_key (str): The API key used for authentication.
        """
        # Initialize the client with required hosts, tenant, and API key
        self.api_key = api_key
        self.iam_host = iam_host
        self.ast_host = ast_host
        self.tenant = tenant
        self.bearer_token = None
        self.is_verbose = is_verbose
        self.token_expiration = None

    def get_bearer_token(self):
        """
        Retrieves a bearer (access) token using the refresh token grant type.
        Constructs the token endpoint URL based on the IAM host and tenant, then sends a POST request
        with the required parameters to obtain a new access token using the stored API key as a refresh token.
        Returns:
            str: The access token if the request is successful.
            None: If the request fails, prints the error and returns None.
        """

        if self.bearer_token is not None and datetime.now() < self.token_expiration:
            return self.bearer_token

        # Construct the URL for token retrieval
        url = f'{self.iam_host}/auth/realms/{self.tenant}/protocol/openid-connect/token'

        data = {  
            'grant_type': 'refresh_token',  
            'client_id': 'ast-app',  
            'refresh_token': f'{self.api_key}'
        }  

        # Send POST request to get the bearer token
        response = requests.post(url, data=data)  

        
        # If successful, return the access token
        if response.status_code == 200:  
            responseJson = response.json()
            expires_in = responseJson['expires_in']
            now = datetime.now()
            # 5 minute expiration buffer
            self.token_expiration = now + timedelta(seconds=expires_in - 300) 
            return response.json()['access_token'] 
        else:  
            # Print error if request failed
            logger.debug(f'Error: {response.status_code} - {response.text}')  
            return None

    def delete_group(self, group_id):
        """
        Delete a group by its ID.

        Args:
            group_id (str): The unique identifier of the group to delete.

        Returns:
            bool: True if the group was deleted successfully (HTTP 204 status code),
                  False otherwise.
        """
        url = f'{self.iam_host}/auth/admin/realms/{self.tenant}/groups/{group_id}'
        headers = {
            'Authorization':
                f'Bearer {self.get_bearer_token()}',
            'Content-Type': 'application/json'
        }
        response = requests.delete(url, headers=headers)
        if response.status_code == 204:
            logger.info(f'Group with ID "{group_id}" deleted successfully.')
            return True
        else:
            logger.debug(f'Error: {response.status_code} - {response.text}')
            return False
        
    def get_groups(self, group_name=None):
        """
        Retrieve groups from the IAM server.
        
        Fetches a list of groups from the configured IAM host for the current tenant.
        Optionally filters the results by group name.
        
        Args:
            group_name (str, optional): The name of a specific group to retrieve. 
                                        If provided, only groups matching this name 
                                        will be returned. Defaults to None.
        
        Returns:
            list: A list of group dictionaries if the request is successful (status code 200).
                  Returns None if the request fails.
        """
        url = f'{self.iam_host}/auth/admin/realms/{self.tenant}/groups'
        headers = {
            'Authorization': f'Bearer {self.get_bearer_token()}',
            'Content-Type': 'application/json'  
        }
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            groups = response.json()
            if group_name:
                groups = [group for group in groups if group['name'] == group_name]
            return groups
        else:
            logger.debug(f'Error: {response.status_code} - {response.text}')
            return None

    def create_group(self, group_name):
        """
        Creates a new group in the IAM system with the specified name.
            bool: True if the group is created successfully (HTTP 201 response).
                  False if the request fails.
        """
        url = f'{self.iam_host}/auth/admin/realms/{self.tenant}/groups'
        headers = { 
            'Authorization': f'Bearer {self.get_bearer_token()}',
            'Content-Type': 'application/json'
        }
        data = {
            "name": group_name            
        }
        logger.debug(f'Attempting to create group with data: {data}')
        response = requests.post(url, headers=headers, json=data)
        if response.status_code == 201:
            logger.info(f'Group "{group_name}" created successfully.')
            return True
        else:
            logger.debug(f'Error: {response.status_code} - {response.text}')
            return False
        
    def assign_roles_to_group(self, group_id, client_id, roles):
        """
        Assign roles to a group in the IAM system.
        This method sends a POST request to assign the specified roles to a group
        for a particular client in the IAM realm.
        Args:
            group_id (str): The unique identifier of the group to assign roles to.
            client_id (str): The unique identifier of the client for which roles are being assigned.
            roles (list): A list of role dictionaries, each containing:
                - id (str): The unique identifier of the role.
                - name (str): The name of the role.
        Returns:
            bool: True if roles were successfully assigned (HTTP 204 response),
                  False otherwise.
        """

        url = f'{self.iam_host}/auth/admin/realms/{self.tenant}/groups/{group_id}/role-mappings/clients/{client_id}'
        headers = {
            'Authorization': f'Bearer {self.get_bearer_token()}',
            'Content-Type': 'application/json'
        }

        # Payload format for assigning roles to group is a list of role objects with id and name, e.g.
        # [
        #     {"id":"002620a4-b0ea-404e-8394-096077c770e4","name":"ast-viewer"},
        #     {"id":"b628cbfc-86de-45d4-8a2a-7affcd8cc5c0","name":"ast-admin"}
        # ]
        data = []
        for role in roles:
            data.append({
                "id": role['id'],
                "name": role['name']
            })
            
        response = requests.post(url, headers=headers, json=data)
        if response.status_code == 204:
            logger.info(f'Roles assigned to group "{group_id}" successfully.')
            return True
        else:
            logger.debug(f'Error: {response.status_code} - {response.text}')
            return False

    def get_roles(self, client_id):
        """
        Retrieves all roles associated with a specific client in the IAM realm.
        
        Args:
            client_id (str): The unique identifier of the client for which to retrieve roles.
        
        Returns:
            dict or None: A dictionary containing the list of roles for the client if the request
                          is successful (HTTP 200), or None if the request fails. The response
                          contains role details from the IAM server.
        """
        # GET https://{{IAM_HOST}}/auth/admin/realms/{{TENANT}}/clients/{{client_id}}/roles
        url = f'{self.iam_host}/auth/admin/realms/{self.tenant}/clients/{client_id}/roles'
        headers = {
            'Authorization': f'Bearer {self.get_bearer_token()}',
            'Content-Type': 'application/json'
        }
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            return response.json()
        else:
            logger.debug(f'Error: {response.status_code} - {response.text}')
            return None
    
    def get_role_id(self, client_id, role_name):
        """
        Retrieve the ID of a role by its name for a given client.

        Args:
            client_id: The identifier of the client.
            role_name (str): The name of the role to search for.

        Returns:
            str or None: The ID of the role if found, otherwise None.
        """
        roles = self.get_roles(client_id)
        for role in roles:
            if role['name'] == role_name:
                return role['id']
        return None 

    def get_client_id(self, client_name):
        """
        Retrieve the internal ID of a client by their identifier string.
        
        Args:
            client_name (str): The client ID to search for.
        
        Returns:
            str or None: The internal ID of the client if found, None otherwise.        
        """
        clients = self.get_clients()
        for client in clients:
            if client['clientId'] == client_name:
                return client['id']
        return None
    
    def get_clients(self):
        """
        Retrieve a list of clients from the IAM realm.
        
        Sends an authenticated GET request to the IAM admin API endpoint to fetch
        all clients configured in the current tenant's realm.
        
        Returns:
            list[dict] | None: A list of client dictionaries containing client configuration details
                if the request is successful (HTTP 200), otherwise None if the request fails.        
        """
        # https://{{cx_iam_host}}/auth/admin/realms/{{cx_tenant}}/clients
        url = f'{self.iam_host}/auth/admin/realms/{self.tenant}/clients'
        headers = {
            'Authorization': f'Bearer {self.get_bearer_token()}',
            'Content-Type': 'application/json'
        }
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            return response.json()
        else:
            logger.debug(f'Error: {response.status_code} - {response.text}')
            return None
        