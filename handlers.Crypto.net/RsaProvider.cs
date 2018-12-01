using Synapse.Core;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

public class RsaProvider : CryptoRuntimeBase
{
    public override ICryptoRuntime Initialize(string config)
    {
        return base.Initialize( config );
    }

    public override ExecuteResult Encrypt(CryptoStartInfo startInfo)
    {
        try
        {
            ParameterInfo parms = DeserializeOrNew<ParameterInfo>( startInfo.Parameters );


            string message = "foo"; // $"SecurityContext: {parms.SecureUserName.ToUnsecureString()}, IsImpersonating: {_identity.IsImpersonating}";
            OnLogMessage( "Logon", message );
            return new ExecuteResult() { Status = StatusType.Success, Message = message };
        }
        catch( Exception ex )
        {
            OnLogMessage( "Logon", ex.Message, ex: ex );
            return new ExecuteResult() { Status = StatusType.Failed, Message = ex.Message };
        }
    }

    public override ExecuteResult Decrypt(CryptoStartInfo startInfo)
    {
        throw new NotImplementedException();
    }

    public override object GetConfigInstance()
    {
        return null;
    }

    public override object GetParametersInstance()
    {
        return new ParameterInfo
        {
            Value = "value to encrypt/decrypt"
        };
    }
}


public class RsaConfigInfo
{
    public string Uri { get; set; }
    public string ContainerName { get; set; }
    public CspProviderFlags CspFlags { get; set; } = CspProviderFlags.NoFlags;
}

public class ParameterInfo
{
    public string Value { get; set; }
}