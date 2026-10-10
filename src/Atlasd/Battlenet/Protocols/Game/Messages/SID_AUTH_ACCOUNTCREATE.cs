using Atlasd.Daemon;
using System;
using System.IO;

namespace Atlasd.Battlenet.Protocols.Game.Messages
{
    class SID_AUTH_ACCOUNTCREATE : Message
    {
        public enum Statuses : UInt32
        {
            Success = 0x00,
            AccountExists = 0x04,
            UsernameTooShort = 0x07,
            UsernameInvalidChars = 0x08,
            UsernameBannedWord = 0x09,
            UsernameShortAlphanumeric = 0x0A,
            UsernameAdjacentPunctuation = 0x0B,
            UsernameTooManyPunctuation = 0x0C,
        }

        public SID_AUTH_ACCOUNTCREATE()
        {
            Id = (byte)MessageIds.SID_AUTH_ACCOUNTCREATE;
            Buffer = new byte[0];
        }

        public SID_AUTH_ACCOUNTCREATE(byte[] buffer)
        {
            Id = (byte)MessageIds.SID_AUTH_ACCOUNTCREATE;
            Buffer = buffer;
        }

        private static Statuses ToStatus(Account.CreateStatus status) => status switch
        {
            Account.CreateStatus.Success => Statuses.Success,
            Account.CreateStatus.UsernameTooShort => Statuses.UsernameTooShort,
            Account.CreateStatus.UsernameInvalidChars => Statuses.UsernameInvalidChars,
            Account.CreateStatus.UsernameBannedWord => Statuses.UsernameBannedWord,
            Account.CreateStatus.UsernameShortAlphanumeric => Statuses.UsernameShortAlphanumeric,
            Account.CreateStatus.UsernameAdjacentPunctuation => Statuses.UsernameAdjacentPunctuation,
            Account.CreateStatus.UsernameTooManyPunctuation => Statuses.UsernameTooManyPunctuation,
            _ => Statuses.AccountExists,
        };

        public override bool Invoke(MessageContext context)
        {
            if (context == null || context.Client == null || !context.Client.Connected || context.Client.GameState == null) return false;

            switch (context.Direction)
            {
                case MessageDirection.ClientToServer:
                    {
                        /**
                         * (UINT8)[32] Salt
                         * (UINT8)[32] Verifier
                         * (STRING)    Username
                         */

                        Logging.WriteLine(Logging.LogLevel.Debug, Logging.LogType.Client_Game, context.Client.RemoteEndPoint, $"[{Common.DirectionToString(context.Direction)}] {MessageName(Id)} ({4 + Buffer.Length} bytes)");

                        var gameState = context.Client.GameState;

                        if (gameState.LogonType != GameState.LogonTypes.NLS)
                            throw new Exceptions.GameProtocolViolationException(context.Client, $"{MessageName(Id)} is only supported for NLS logon");

                        if (gameState.ActiveAccount != null)
                            throw new Exceptions.GameProtocolViolationException(context.Client, $"{MessageName(Id)} cannot be sent after logging into an account");

                        if (Buffer.Length < 66)
                            throw new Exceptions.GameProtocolViolationException(context.Client, $"{MessageName(Id)} buffer must be at least 66 bytes");

                        using var m = new MemoryStream(Buffer);
                        using var r = new BinaryReader(m);

                        var salt = r.ReadBytes(NLSServer.ValueLength);
                        var verifier = r.ReadBytes(NLSServer.ValueLength);
                        var username = r.ReadString();

                        var createStatus = Account.TryCreate(username, new byte[20], out var account);
                        if (createStatus == Account.CreateStatus.Success)
                        {
                            account.Set(Account.NLSSaltKey, salt);
                            account.Set(Account.NLSVerifierKey, verifier);
                        }

                        return new SID_AUTH_ACCOUNTCREATE().Invoke(new MessageContext(context.Client, MessageDirection.ServerToClient, new System.Collections.Generic.Dictionary<string, object> {{ "status", ToStatus(createStatus) }}));
                    }
                case MessageDirection.ServerToClient:
                    {
                        /**
                         * (UINT32) Status
                         */

                        var status = (Statuses)context.Arguments["status"];

                        Buffer = new byte[4];

                        using var m = new MemoryStream(Buffer);
                        using var w = new BinaryWriter(m);

                        w.Write((UInt32)status);

                        Logging.WriteLine(Logging.LogLevel.Debug, Logging.LogType.Client_Game, context.Client.RemoteEndPoint, $"[{Common.DirectionToString(context.Direction)}] {MessageName(Id)} ({4 + Buffer.Length} bytes) (status: 0x{(UInt32)status:X8})");
                        context.Client.Send(ToByteArray(context.Client.ProtocolType));
                        return true;
                    }
            }

            return false;
        }
    }
}
