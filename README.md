# Znuny OAuth2 Sync
A module to sync user from OAuth2

## Example
Example configuration in Config.pm:
```
# OAuth2 Auth Modul

$Self->{'AuthModule'} =
    'Kernel::System::Auth::OAuth2AuthSync';

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