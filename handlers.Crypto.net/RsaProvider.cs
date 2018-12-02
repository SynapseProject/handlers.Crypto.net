using System;
using System.Collections.Generic;
using System.Security.Cryptography;

using Synapse.Core;

using Zephyr.Crypto;


public class RsaProvider : CryptoRuntimeBase
{
    IRsaConfig _config = null;
    public override ICryptoRuntime Initialize(string config)
    {
        //todo: this is a junky way to do this
        if( config.Contains( "Uri: " ) )
            _config = DeserializeOrDefault<RsaConfigInfoFile>( config );
        else
            _config = DeserializeOrDefault<RsaConfigInfoContainer>( config );

        if( _config == null )
            throw new Exception( "Could not deserialize config." );

        return this;
    }

    public override ExecuteResult Encrypt(CryptoStartInfo startInfo)
    {
        try
        {
            CryptoParameters parms = DeserializeOrNew<CryptoParameters>( startInfo.Parameters );

            string value = _config is RsaConfigInfoFile ?
                RsaHelpers.EncryptFromFileKeys( ((RsaConfigInfoFile)_config).Uri, parms.Value, _config.CspFlags ) :
                RsaHelpers.EncryptFromContainerKeys( ((RsaConfigInfoContainer)_config).ContainerName, parms.Value, _config.CspFlags );

            return new ExecuteResult() { Status = StatusType.Success, ExitData = value };
        }
        catch( Exception ex )
        {
            OnLogMessage( "Encrypt", ex.Message, ex: ex );
            return new ExecuteResult() { Status = StatusType.Failed, Message = ex.Message };
        }
    }

    public override ExecuteResult Decrypt(CryptoStartInfo startInfo)
    {
        try
        {
            CryptoParameters parms = DeserializeOrNew<CryptoParameters>( startInfo.Parameters );

            string value = _config is RsaConfigInfoFile ?
                RsaHelpers.DecryptFromFileKeys( ((RsaConfigInfoFile)_config).Uri, parms.Value, _config.CspFlags ) :
                RsaHelpers.DecryptFromContainerKeys( ((RsaConfigInfoContainer)_config).ContainerName, parms.Value, _config.CspFlags );

            return new ExecuteResult() { Status = StatusType.Success, ExitData = value };
        }
        catch( Exception ex )
        {
            OnLogMessage( "Decrypt", ex.Message, ex: ex );
            return new ExecuteResult() { Status = StatusType.Failed, Message = ex.Message };
        }
    }

    public override object GetConfigInstance()
    {
        return new Dictionary<string, IRsaConfig>
        {
            {
                "File", new RsaConfigInfoFile
                {
                    Uri = "Filepath to RSA key file; http support in future.",
                    CspFlags = CspProviderFlags.NoFlags
                }
            },
            {
                "Container", new RsaConfigInfoContainer
                {
                    ContainerName = "RSA-supported container name.",
                    CspFlags = CspProviderFlags.NoFlags
                }
            }
        };
    }

    public override object GetParametersInstance()
    {
        return new CryptoParameters
        {
            Value = "value to encrypt/decrypt"
        };
    }
}

public interface IRsaConfig
{
    CspProviderFlags CspFlags { get; set; }
}

public class RsaConfigInfoFile : IRsaConfig
{
    public string Uri { get; set; }
    public CspProviderFlags CspFlags { get; set; } = CspProviderFlags.NoFlags;
}

public class RsaConfigInfoContainer : IRsaConfig
{
    public string ContainerName { get; set; }
    public CspProviderFlags CspFlags { get; set; } = CspProviderFlags.NoFlags;
}