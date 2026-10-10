using Atlasd.Battlenet.Exceptions;
using Atlasd.Daemon;
using System;
using System.Collections.Generic;
using System.IO;

namespace Atlasd.Battlenet.Protocols.Game.Messages
{
    class SID_AUTH_ACCOUNTLOGON : Message
    {
        public enum Statuses : UInt32
        {
            Success = 0x00,
            DoesNotExist = 0x01,
        }

        public SID_AUTH_ACCOUNTLOGON()
        {
            Id = (byte)MessageIds.SID_AUTH_ACCOUNTLOGON;
            Buffer = new byte[0];
        }

        public SID_AUTH_ACCOUNTLOGON(byte[] buffer)
        {
            Id = (byte)MessageIds.SID_AUTH_ACCOUNTLOGON;
            Buffer = buffer;
        }

        private static SID_AUTH_ACCOUNTLOGONPROOF.Statuses ToLogonStatus(Account.CreateStatus status) => status switch
        {
            Account.CreateStatus.UsernameTooShort => SID_AUTH_ACCOUNTLOGONPROOF.Statuses.UsernameTooShort,
            Account.CreateStatus.UsernameInvalidChars => SID_AUTH_ACCOUNTLOGONPROOF.Statuses.UsernameInvalidChars,
            Account.CreateStatus.UsernameBannedWord => SID_AUTH_ACCOUNTLOGONPROOF.Statuses.UsernameBannedWord,
            Account.CreateStatus.UsernameShortAlphanumeric => SID_AUTH_ACCOUNTLOGONPROOF.Statuses.UsernameShortAlphanumeric,
            Account.CreateStatus.UsernameAdjacentPunctuation => SID_AUTH_ACCOUNTLOGONPROOF.Statuses.UsernameAdjacentPunctuation,
            Account.CreateStatus.UsernameTooManyPunctuation => SID_AUTH_ACCOUNTLOGONPROOF.Statuses.UsernameTooManyPunctuation,
            _ => SID_AUTH_ACCOUNTLOGONPROOF.Statuses.BadPassword,
        };

        private static bool Reply(MessageContext context, SID_AUTH_ACCOUNTLOGONPROOF.Statuses status)
        {
            return new SID_AUTH_ACCOUNTLOGONPROOF().Invoke(new MessageContext(context.Client, MessageDirection.ServerToClient, new Dictionary<string, object> {{ "status", status }}));
        }

        public override bool Invoke(MessageContext context)
        {
            if (context == null || context.Client == null || !context.Client.Connected || context.Client.GameState == null) return false;

            switch (context.Direction)
            {
                case MessageDirection.ClientToServer:
                    return ClientToServer(context);
                case MessageDirection.ServerToClient:
                    return ServerToClient(context);
            }

            return false;
        }

        private bool ServerToClient(MessageContext context)
        {
            /**
             * (UINT32)    Status
             * (UINT8)[32] Salt
             * (UINT8)[32] Server key
             */

            var status = (Statuses)context.Arguments["status"];

            Buffer = new byte[4 + 2 * NLSServer.ValueLength];

            using var m = new MemoryStream(Buffer);
            using var w = new BinaryWriter(m);

            w.Write((UInt32)status);
            if (status == Statuses.Success)
            {
                w.Write((byte[])context.Arguments["salt"]);
                w.Write((byte[])context.Arguments["serverKey"]);
            }

            Logging.WriteLine(Logging.LogLevel.Debug, Logging.LogType.Client_Game, context.Client.RemoteEndPoint, $"[{Common.DirectionToString(context.Direction)}] {MessageName(Id)} ({4 + Buffer.Length} bytes) (status: 0x{(UInt32)status:X8})");
            context.Client.Send(ToByteArray(context.Client.ProtocolType));
            return true;
        }

        private static bool ReplyNLS(MessageContext context, Statuses status, byte[] salt = null, byte[] serverKey = null)
        {
            return new SID_AUTH_ACCOUNTLOGON().Invoke(new MessageContext(context.Client, MessageDirection.ServerToClient, new Dictionary<string, object>() {{ "status", status }, { "salt", salt }, { "serverKey", serverKey }}));
        }

        /// <summary>
        /// Makes the account active for the client; returns false if the client could not be registered as online.
        /// </summary>
        public static bool Activate(MessageContext context, Account account)
        {
            var gameState = context.Client.GameState;

            gameState.ActiveAccount = account;
            gameState.FailedLogons = (UInt32)account.Get(Account.FailedLogonsKey, (UInt32)0);
            gameState.LastLogon = (DateTime)account.Get(Account.LastLogonKey, DateTime.Now);

            account.Set(Account.IPAddressKey, context.Client.RemoteEndPoint.ToString().Split(":")[0]);
            account.Set(Account.LastLogonKey, DateTime.Now);
            account.Set(Account.PortKey, context.Client.RemoteEndPoint.ToString().Split(":")[1]);

            var serial = 1;
            var onlineName = gameState.Username;
            while (!Battlenet.Common.ActiveAccounts.TryAdd(onlineName, account)) onlineName = $"{gameState.Username}#{++serial}";
            gameState.OnlineName = onlineName;

            gameState.Username = (string)account.Get(Account.UsernameKey, gameState.Username);

            if (!Battlenet.Common.ActiveGameStates.TryAdd(gameState.OnlineName, gameState))
            {
                Logging.WriteLine(Logging.LogLevel.Error, Logging.LogType.Client_Game, context.Client.RemoteEndPoint, $"Failed to add game state to active game state cache");
                Battlenet.Common.ActiveAccounts.TryRemove(onlineName, out _);
                return false;
            }

            Logging.WriteLine(Logging.LogLevel.Info, Logging.LogType.Client_Game, context.Client.RemoteEndPoint, $"Account [{gameState.Username}] logon success as [{gameState.OnlineName}]");
            return true;
        }

        private bool ClientToServer(MessageContext context)
        {
            Logging.WriteLine(Logging.LogLevel.Debug, Logging.LogType.Client_Game, context.Client.RemoteEndPoint, $"[{Common.DirectionToString(context.Direction)}] {MessageName(Id)} ({4 + Buffer.Length} bytes)");

            var gameState = context.Client.GameState;

            if (Buffer.Length < 34)
                throw new GameProtocolViolationException(context.Client, $"{MessageName(Id)} buffer must be at least 34 bytes");

            if (gameState.ActiveAccount != null)
                throw new GameProtocolViolationException(context.Client, $"{MessageName(Id)} cannot be sent after logging into an account");

            if (gameState.Product == Product.ProductCode.WarcraftIIIDemo &&
                Settings.GetBoolean(new[] { "battlenet", "emulation", "name_only_logon", "W3DM" }, false, true))
                return NameOnlyLogon(context);

            if (gameState.LogonType != GameState.LogonTypes.NLS)
                throw new GameProtocolViolationException(context.Client, $"{MessageName(Id)} is only supported for NLS logon");

            /**
             * (UINT8)[32] Client key
             * (STRING)    Username
             */

            using var m = new MemoryStream(Buffer);
            using var r = new BinaryReader(m);

            var clientKey = r.ReadBytes(NLSServer.ValueLength);
            gameState.Username = r.ReadString();
            gameState.NLS = null;

            if (!Battlenet.Common.AccountsDb.TryGetValue(gameState.Username, out Account account) || account == null ||
                !(account.Get(Account.NLSSaltKey, new byte[0]) is byte[] salt) || salt.Length != NLSServer.ValueLength ||
                !(account.Get(Account.NLSVerifierKey, new byte[0]) is byte[] verifier) || verifier.Length != NLSServer.ValueLength)
            {
                Logging.WriteLine(Logging.LogLevel.Info, Logging.LogType.Client_Game, context.Client.RemoteEndPoint, $"Account [{gameState.Username}] does not exist or has no NLS credentials");
                return ReplyNLS(context, Statuses.DoesNotExist);
            }

            gameState.NLSClientKey = clientKey;
            gameState.NLS = new NLSServer(salt, verifier);
            return ReplyNLS(context, Statuses.Success, gameState.NLS.Salt, gameState.NLS.ServerKey);
        }

        private bool NameOnlyLogon(MessageContext context)
        {
            var gameState = context.Client.GameState;

            /**
             * (UINT8)[32] Client key
             * (STRING)    Username
             *
             * The Warcraft III demo has no password field. It sends this message and treats the
             * reply to it as SID_AUTH_ACCOUNTLOGONPROOF; it never sends a proof of its own.
             */

            using var m = new MemoryStream(Buffer);
            using var r = new BinaryReader(m);

            r.ReadBytes(32);
            gameState.Username = r.ReadString();

            if (!Battlenet.Common.AccountsDb.TryGetValue(gameState.Username, out Account account) || account == null)
            {
                var createStatus = Account.TryCreate(gameState.Username, new byte[20], out account);
                if (createStatus != Account.CreateStatus.Success)
                {
                    Logging.WriteLine(Logging.LogLevel.Info, Logging.LogType.Client_Game, context.Client.RemoteEndPoint, $"Account [{gameState.Username}] could not be created for name-only logon: {createStatus}");
                    return Reply(context, ToLogonStatus(createStatus));
                }

                account.Set(Account.FlagsKey, Account.Flags.None);
                account.Set(Account.NameOnlyKey, 1);
            }

            var flags = (Account.Flags)account.Get(Account.FlagsKey, Account.Flags.None);
            if ((int)account.Get(Account.NameOnlyKey, 0) == 0 || (flags & Account.Flags.Closed) != 0)
            {
                Logging.WriteLine(Logging.LogLevel.Info, Logging.LogType.Client_Game, context.Client.RemoteEndPoint, $"Account [{gameState.Username}] cannot be used for name-only logon");
                return Reply(context, SID_AUTH_ACCOUNTLOGONPROOF.Statuses.BadPassword);
            }

            if (!Activate(context, account)) return false;

            return Reply(context, SID_AUTH_ACCOUNTLOGONPROOF.Statuses.Success);
        }
    }
}
