using Atlasd.Daemon;
using System;
using System.Collections.Generic;
using System.IO;

namespace Atlasd.Battlenet.Protocols.Game.Messages
{
    class SID_AUTH_ACCOUNTLOGONPROOF : Message
    {
        public enum Statuses : UInt32
        {
            Success = 0x00,
            BadPassword = 0x02,
            UsernameTooShort = 0x07,
            UsernameInvalidChars = 0x08,
            UsernameBannedWord = 0x09,
            UsernameShortAlphanumeric = 0x0A,
            UsernameAdjacentPunctuation = 0x0B,
            UsernameTooManyPunctuation = 0x0C,
        }

        public SID_AUTH_ACCOUNTLOGONPROOF()
        {
            Id = (byte)MessageIds.SID_AUTH_ACCOUNTLOGONPROOF;
            Buffer = new byte[0];
        }

        public SID_AUTH_ACCOUNTLOGONPROOF(byte[] buffer)
        {
            Id = (byte)MessageIds.SID_AUTH_ACCOUNTLOGONPROOF;
            Buffer = buffer;
        }

        public override bool Invoke(MessageContext context)
        {
            if (context == null || context.Client == null || !context.Client.Connected || context.Client.GameState == null) return false;

            if (context.Direction == MessageDirection.ClientToServer)
                return ClientToServer(context);

            /**
             * (UINT32)    Status
             * (UINT8)[20] Server password proof
             *
             * The clients also read an additional information string when the status is 0x0F; it is not sent here.
             */

            var status = (Statuses)context.Arguments["status"];
            var serverProof = context.Arguments.TryGetValue("serverProof", out var proofValue) && proofValue is byte[] proofBytes ? proofBytes : new byte[NLSServer.ProofLength];

            Buffer = new byte[24];

            using var m = new MemoryStream(Buffer);
            using var w = new BinaryWriter(m);

            w.Write((UInt32)status);
            w.Write(serverProof);

            Logging.WriteLine(Logging.LogLevel.Debug, Logging.LogType.Client_Game, context.Client.RemoteEndPoint, $"[{Common.DirectionToString(context.Direction)}] {MessageName(Id)} ({4 + Buffer.Length} bytes) (status: 0x{(UInt32)status:X8})");
            context.Client.Send(ToByteArray(context.Client.ProtocolType));
            return true;
        }

        private bool ClientToServer(MessageContext context)
        {
            /**
             * (UINT8)[20] Client password proof
             */

            Logging.WriteLine(Logging.LogLevel.Debug, Logging.LogType.Client_Game, context.Client.RemoteEndPoint, $"[{Common.DirectionToString(context.Direction)}] {MessageName(Id)} ({4 + Buffer.Length} bytes)");

            var gameState = context.Client.GameState;

            if (gameState.NLS == null || gameState.NLSClientKey == null)
                throw new Exceptions.GameProtocolViolationException(context.Client, $"{MessageName(Id)} must follow {MessageName((byte)MessageIds.SID_AUTH_ACCOUNTLOGON)}");

            if (gameState.ActiveAccount != null)
                throw new Exceptions.GameProtocolViolationException(context.Client, $"{MessageName(Id)} cannot be sent after logging into an account");

            if (Buffer.Length < NLSServer.ProofLength)
                throw new Exceptions.GameProtocolViolationException(context.Client, $"{MessageName(Id)} buffer must be at least {NLSServer.ProofLength} bytes");

            var nls = gameState.NLS;
            gameState.NLS = null;

            var clientProof = new byte[NLSServer.ProofLength];
            Array.Copy(Buffer, clientProof, clientProof.Length);

            Battlenet.Common.AccountsDb.TryGetValue(gameState.Username, out Account account);
            var flags = account == null ? Account.Flags.None : (Account.Flags)account.Get(Account.FlagsKey, Account.Flags.None);

            if (account == null || (flags & Account.Flags.Closed) != 0 || !nls.Verify(gameState.Username, gameState.NLSClientKey, clientProof, out var serverProof))
            {
                Logging.WriteLine(Logging.LogLevel.Info, Logging.LogType.Client_Game, context.Client.RemoteEndPoint, $"Account [{gameState.Username}] logon failed: bad password or closed account");
                if (account != null) account.Set(Account.FailedLogonsKey, (long)account.Get(Account.FailedLogonsKey, (long)0) + 1);
                return new SID_AUTH_ACCOUNTLOGONPROOF().Invoke(new MessageContext(context.Client, MessageDirection.ServerToClient, new Dictionary<string, object> {{ "status", Statuses.BadPassword }}));
            }

            if (!SID_AUTH_ACCOUNTLOGON.Activate(context, account)) return false;

            return new SID_AUTH_ACCOUNTLOGONPROOF().Invoke(new MessageContext(context.Client, MessageDirection.ServerToClient, new Dictionary<string, object> {{ "status", Statuses.Success }, { "serverProof", serverProof }}));
        }
    }
}
