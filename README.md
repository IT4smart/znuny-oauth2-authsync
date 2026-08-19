# Znuny OAuth2 Sync
A module to sync user from OAuth2

## Example
Example configuration in Config.pm:
```
# OAuth2 AuthSync Modul

$Self->{'AuthSyncModule'} = 'Kernel::System::AuthSync::OAuth2AuthSync';

# root@localhost niemals überschreiben

$Self->{'OAuth2AuthSync::ProtectedUsers'} = [
    'root@localhost',
];

# Mapping Entra → Znuny

$Self->{'OAuth2AuthSync::GroupMapping'} = {

    # Znuny Users
    '6230639a-6566-4074-825b-6d05fd7ad1bc'
        => 'users',

    # Znuny Admins
    '6e69370d-87df-40b3-9b2f-809eb4a8d53d'
        => 'admin',

};
```

## Example Nginx
Example header configuration in Nginx
```
auth_request_set $user $upstream_http_x_auth_request_user;
auth_request_set $email $upstream_http_x_auth_request_email;
auth_request_set $groups $upstream_http_x_auth_request_groups;
auth_request_set $access_token $upstream_http_x_auth_request_access_token;

proxy_set_header X-Remote-User $user;
proxy_set_header X-Remote-Email $email;
proxy_set_header X-Remote-Groups $groups;
proxy_set_header X-Access-Token $access_token;
```