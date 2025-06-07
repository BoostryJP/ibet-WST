## Error Code
This is a definition list of errors to be thrown when transaction reverts.
Developers will receive error msg as code, and each error code is described below, including description of situation and possible causes.

### Access Error
- [Ownable (50XXXX)](#ownable-50XXXX)

### Ownable (50XXXX)

#### onlyOwner (5000XX)
| Code       | Situation                             | Possible causes | 
|------------|---------------------------------------|-----------------|
| **500001** | Message sender is not contract owner. | -               |

#### transferOwnership (5001XX)
| Code       | Situation                     | Possible causes | 
|------------|-------------------------------|-----------------|
| **500101** | New owner address is not set. | -               |
