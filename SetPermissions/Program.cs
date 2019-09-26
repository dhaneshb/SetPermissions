using System;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.ServiceProcess;

namespace SetPermissions
{
    class Program
    {
        static void Main(string[] args)
        {
            SetServicePermissions("RabbitMQ", "TestUser");
        }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Interoperability", "CA1404:CallGetLastErrorImmediatelyAfterPInvoke")]
        public static void SetServicePermissions(string service, string username)
        {
            System.ServiceProcess.ServiceController sc = new System.ServiceProcess.ServiceController(service);
            ServiceControllerStatus status = sc.Status;
            
            byte[] psd = new byte[0];
            uint bufSizeNeeded;
            bool ok = ServiceAccountHelper.QueryServiceObjectSecurity(sc.ServiceHandle, SecurityInfos.DiscretionaryAcl, psd, 0, out bufSizeNeeded);
            if (!ok)
            {
                int err = Marshal.GetLastWin32Error();
                if (err == 122 || err == 0)
                { // ERROR_INSUFFICIENT_BUFFER
                  // expected; now we know bufsize
                    psd = new byte[bufSizeNeeded];
                    ok = ServiceAccountHelper.QueryServiceObjectSecurity(sc.ServiceHandle, SecurityInfos.DiscretionaryAcl, psd, bufSizeNeeded, out bufSizeNeeded);
                }
                else
                {
                    throw new ApplicationException("error calling QueryServiceObjectSecurity() to get DACL for " + username + ": error code=" + err);
                }
            }
            if (!ok)
                throw new ApplicationException("error calling QueryServiceObjectSecurity(2) to get DACL for " + username + ": error code=" + Marshal.GetLastWin32Error());

            // get security descriptor via raw into DACL form so ACE
            // ordering checks are done for us.
            RawSecurityDescriptor rsd = new RawSecurityDescriptor(psd, 0);
            RawAcl racl = rsd.DiscretionaryAcl;
            DiscretionaryAcl dacl = new DiscretionaryAcl(false, false, racl);

            // Add start/stop/read access
            NTAccount acct = new NTAccount(username);
            
            SecurityIdentifier sid = (SecurityIdentifier)acct.Translate(typeof(SecurityIdentifier));
         
            dacl.AddAccess(AccessControlType.Allow, sid, (int)ServiceAccountHelper.SERVICE_ACCESS.SERVICE_START, InheritanceFlags.None, PropagationFlags.None);
            dacl.AddAccess(AccessControlType.Allow, sid, (int)ServiceAccountHelper.SERVICE_ACCESS.SERVICE_STOP, InheritanceFlags.None, PropagationFlags.None);

            // convert discretionary ACL back to raw form; looks like via byte[] is only way
            byte[] rawdacl = new byte[dacl.BinaryLength];
            dacl.GetBinaryForm(rawdacl, 0);
            rsd.DiscretionaryAcl = new RawAcl(rawdacl, 0);

            // set raw security descriptor on service again
            byte[] rawsd = new byte[rsd.BinaryLength];
            rsd.GetBinaryForm(rawsd, 0);
            ok = ServiceAccountHelper.SetServiceObjectSecurity(sc.ServiceHandle, SecurityInfos.DiscretionaryAcl, rawsd);
            if (!ok)
            {
                throw new ApplicationException("error calling SetServiceObjectSecurity(); error code=" + Marshal.GetLastWin32Error());
            }
        }

    }
}
