using System;
using System.Runtime.InteropServices;

namespace SetPermissions
{
    public static class ServiceAccountHelper
    {
        [Flags]
        public enum SERVICE_ACCESS : uint
        {
            STANDARD_RIGHTS_REQUIRED = 0xF0000,
            SERVICE_QUERY_CONFIG = 0x00001,
            SERVICE_CHANGE_CONFIG = 0x00002,
            SERVICE_QUERY_STATUS = 0x00004,
            SERVICE_ENUMERATE_DEPENDENTS = 0x00008,
            SERVICE_START = 0x00010,
            SERVICE_STOP = 0x00020,
            SERVICE_PAUSE_CONTINUE = 0x00040,
            SERVICE_INTERROGATE = 0x00080,
            SERVICE_USER_DEFINED_CONTROL = 0x00100,
            SERVICE_ALL_ACCESS = (STANDARD_RIGHTS_REQUIRED |
                              SERVICE_QUERY_CONFIG |
                              SERVICE_CHANGE_CONFIG |
                              SERVICE_QUERY_STATUS |
                              SERVICE_ENUMERATE_DEPENDENTS |
                              SERVICE_START |
                              SERVICE_STOP |
                              SERVICE_PAUSE_CONTINUE |
                              SERVICE_INTERROGATE |
                              SERVICE_USER_DEFINED_CONTROL)
        }
        [StructLayoutAttribute(LayoutKind.Sequential)]
       public struct SECURITY_DESCRIPTOR
        {
            public byte revision;
            public byte size;
            public short control;
            private IntPtr owner;
            private IntPtr group;
            private IntPtr sacl;
            private IntPtr dacl;
        }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Design", "CA1060:MovePInvokesToNativeMethodsClass")]
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Interoperability", "CA1401:PInvokesShouldNotBeVisible")]
        [DllImport("advapi32.dll", SetLastError = true)]
       public static extern bool QueryServiceObjectSecurity(IntPtr serviceHandle,
            System.Security.AccessControl.SecurityInfos secInfo,
            ref SECURITY_DESCRIPTOR lpSecDesrBuf,
            uint bufSize,
            out uint bufSizeNeeded);

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Design", "CA1060:MovePInvokesToNativeMethodsClass")]
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Interoperability", "CA1401:PInvokesShouldNotBeVisible")]
        [DllImport("advapi32.dll", SetLastError = true)]
       public static extern bool QueryServiceObjectSecurity(SafeHandle serviceHandle,
            System.Security.AccessControl.SecurityInfos secInfo,
            byte[] lpSecDesrBuf,
            uint bufSize,
            out uint bufSizeNeeded);

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Interoperability", "CA1401:PInvokesShouldNotBeVisible")]
        [DllImport("advapi32.dll", SetLastError = true)]
       public static extern bool SetServiceObjectSecurity(SafeHandle serviceHandle,
            System.Security.AccessControl.SecurityInfos secInfos,
            byte[] lpSecDesrBuf);
    }
}
