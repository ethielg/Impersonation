using System;
using System.Threading;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Security.Permissions;

[assembly:SecurityPermissionAttribute(SecurityAction.RequestMinimum, UnmanagedCode=true)]
[assembly:PermissionSetAttribute(SecurityAction.RequestMinimum, Name = "FullTrust")]
namespace QAWEB
{

	/// <summary>
	/// Credentials for doing NT impersonation
	/// </summary>
	public struct NTCredential
	{
		public NTCredential(string userName, string password, string domainName)
		{
			this.UserName = userName;
			this.Password = password;
			this.DomainName = domainName;
		}
		public string UserName, Password, DomainName;
	}

	/// <summary>
	/// Summary description for Impersonate.
	/// </summary>
	public unsafe struct ImpersonationData
	{
		public IntPtr TokenHandle;
		public IntPtr DupeTokenHandle;
		public WindowsIdentity Identity;
		public WindowsImpersonationContext ImpersonatedUser;
		public ImpersonationData(IntPtr TokenHandle, IntPtr DupeTokenHandle, WindowsIdentity Identity, WindowsImpersonationContext ImpersonatedUser)
		{
			this.TokenHandle = TokenHandle;
			this.DupeTokenHandle = DupeTokenHandle;
			this.Identity = Identity;
			this.ImpersonatedUser = ImpersonatedUser;
		}
	}
	
	public unsafe class Impersonation
	{
		[DllImport("advapi32.dll", SetLastError=true)]
		public static extern bool LogonUser(String lpszUsername, String lpszDomain, String lpszPassword, 
			int dwLogonType, int dwLogonProvider, ref IntPtr phToken);

		[DllImport("kernel32.dll", CharSet=System.Runtime.InteropServices.CharSet.Auto)]
		private unsafe static extern int FormatMessage(int dwFlags, ref IntPtr lpSource, 
			int dwMessageId, int dwLanguageId, ref String lpBuffer, int nSize, IntPtr *Arguments);

		[DllImport("kernel32.dll", CharSet=CharSet.Auto)]
		public extern static bool CloseHandle(IntPtr handle);

		[DllImport("advapi32.dll", CharSet=CharSet.Auto, SetLastError=true)]
		public extern static bool DuplicateToken(IntPtr ExistingTokenHandle, 
			int SECURITY_IMPERSONATION_LEVEL, ref IntPtr DuplicateTokenHandle);

		public Impersonation()
		{
			//
			// TODO: Add constructor logic here
			//
		}
		public ImpersonationData Impersonate(NTCredential credential)
		{
			return DoImpersonation(credential);
		}
    
		//TODO: Should be internal.  Need to figure out how to get to the companies list before they are fully auth'd.
//		public ImpersonationData ImpersonateMasterUser()
//		{
//			ImpersonationData impData = DoImpersonation(Registry.GetInitialCredentials());
//			impData.Identity.Impersonate();
//			return impData;
//		}
    
		ImpersonationData DoImpersonation(NTCredential credential)
		{
			IntPtr tokenHandle = new IntPtr(0);
			IntPtr dupeTokenHandle = new IntPtr(0);
			WindowsImpersonationContext impersonatedUser = null;
			// Get the user token for the specified user, machine, and password using the 
			// unmanaged LogonUser method.
			const int LOGON32_LOGON_NETWORK_CLEARTEXT = 8;
			const int LOGON32_LOGON_INTERACTIVE = 2;
			//const int LOGON32_LOGON_NEW_CREDENTIALS = 9;
			//const int LOGON32_PROVIDER_WINNT50 = 3;
			const int LOGON32_PROVIDER_DEFAULT = 0;
			//This parameter causes LogonUser to create a primary token.
			//const int LOGON32_LOGON_NETWORK = 3;
			const int SecurityImpersonation = 2;
			// Call LogonUser to obtain a handle to an access token.
			bool returnValue = LogonUser(credential.UserName, credential.DomainName, credential.Password, 
				LOGON32_LOGON_INTERACTIVE , LOGON32_PROVIDER_DEFAULT,
				ref tokenHandle);
              
			if (false == returnValue)
			{
				int ret = Marshal.GetLastWin32Error();
				throw new Exception(String.Format("LogonUser failed with error code : {0}, message: {1}", ret, GetErrorMessage(ret)));
			}

			bool retVal = DuplicateToken(tokenHandle, SecurityImpersonation, ref dupeTokenHandle);
			if (false == retVal)
			{
				CloseHandle(tokenHandle);
			}

           
      
			// The token that is passed to the following constructor must 
			// be a primary token in order to use it for impersonation.
			WindowsIdentity newId = new WindowsIdentity(dupeTokenHandle);
			impersonatedUser = newId.Impersonate();
			return new ImpersonationData(tokenHandle,dupeTokenHandle,newId,impersonatedUser);  
		}

		public unsafe static string GetErrorMessage(int errorCode)
		{
			int FORMAT_MESSAGE_ALLOCATE_BUFFER = 0x00000100;
			int FORMAT_MESSAGE_IGNORE_INSERTS  = 0x00000200;
			int FORMAT_MESSAGE_FROM_SYSTEM     = 0x00001000;

			int messageSize = 255;
			String lpMsgBuf = "";
			int dwFlags     = FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS;

			IntPtr ptrlpSource  = IntPtr.Zero;
			IntPtr prtArguments = IntPtr.Zero;
        
			int retVal = FormatMessage(dwFlags, ref ptrlpSource, errorCode, 0, ref lpMsgBuf, messageSize, &prtArguments);
			if (0 == retVal)
			{
				throw new Exception("Failed to format message for error code " + errorCode + ". ");
			}

			return lpMsgBuf;
		}
		

		public bool Unimpersonate(ImpersonationData impersonationData)
		{
			if (impersonationData.ImpersonatedUser != null)
			{
				// Stop impersonating the user.
				impersonationData.ImpersonatedUser.Undo();

				// Free the tokens.
				if (impersonationData.TokenHandle != IntPtr.Zero)
					CloseHandle(impersonationData.TokenHandle );
				if (impersonationData.DupeTokenHandle != IntPtr.Zero) 
					CloseHandle(impersonationData.DupeTokenHandle);
				return true;
			}
			else
				return false;
		}

	}

}

