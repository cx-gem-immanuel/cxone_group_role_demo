from cxsupport import CheckmarxClient
from logsupport import setup_logger  

logger = setup_logger()

if __name__ == "__main__":

    cx_iam_host = "https://CXONE_IAM_HOST"
    cx_ast_host = "https://CXONE_AST_HOST"
    cx_tenant = "TENANT_NAME"
    cx_api_key = "API_KEY"

    # Initialize the CxSupport client
    cx_client = CheckmarxClient(cx_iam_host, cx_ast_host, cx_tenant, cx_api_key, True)

    # Desired group name and roles to assign to the group
    group_name = "Example Group"
    desired_roles = ["ast-viewer"]

    #  Get the client ID for the CxOne application ("ast-app")
    client_id = cx_client.get_client_id("ast-app")
    logger.debug(f"Client ID for ast-app: {client_id}")

    # Add desired roles to array.
    roles = []
    for role_name in desired_roles:
        role_id = cx_client.get_role_id(client_id, role_name)
        if role_id:
            roles.append({"id": role_id, "name": role_name})

    # Create desired group
    logger.debug(f"Creating group '{group_name}'")
    is_created = cx_client.create_group(group_name)
    if is_created:
        logger.info(f"Group '{group_name}' created.")        
        # Assign roles to group
        # Get the group ID for the newly created group
        new_group = cx_client.get_groups(group_name)
        if new_group:
            new_group_id = new_group[0]['id']
            logger.debug(f"New group '{group_name}' has ID {new_group_id}. Assigning roles...")
            success = cx_client.assign_roles_to_group(new_group_id, client_id, roles)
            if success:
                logger.info(f"Roles assigned to group '{group_name}' successfully.")
            else:
                logger.error(f"Failed to assign roles to group '{group_name}'.")
        else:
            logger.error(f"Failed to retrieve newly created group '{group_name}' for role assignment.")       
    else:
        logger.error(f"Failed to create group '{group_name}'.")