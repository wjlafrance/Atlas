using Atlasd.Daemon;
using System;
using System.Collections.Generic;
using System.IO;

namespace Atlasd.Battlenet.Protocols.Game.Messages
{
    class SID_AUTH_ACCOUNTCHANGE : Message
    {
        public enum Statuses : UInt32
        {
            Success = 0x00,
            DoesNotExist = 0x01,
        }

        public SID_AUTH_ACCOUNTCHANGE()
        {
            Id = (byte)MessageIds.SID_AUTH_ACCOUNTCHANGE;
            Buffer = new byte[0];
        }

        public SID_AUTH_ACCOUNTCHANGE(byte[] buffer)
        {
            Id = (byte)MessageIds.SID_AUTH_ACCOUNTCHANGE;
            Buffer = buffer;
        }

        public override bool Invoke(MessageContext context)
        {
            if (context == null || context.Client == null || !context.Client.Connected || context.Client.GameState == null) return false;

            switch (context.Direction)
            {
                case MessageDirection.ClientToServer:
                    {
                        /**
                         * (UINT8)[32] Client key
                         * (STRING)    Username
                         */

                        Logging.WriteLine(Logging.LogLevel.Debug, Logging.LogType.Client_Game, context.Client.RemoteEndPoint, $"[{Common.DirectionToString(context.Direction)}] {MessageName(Id)} ({4 + Buffer.Length} bytes)");

                        var gameState = context.Client.GameState;

                        if (gameState.LogonType != GameState.LogonTypes.NLS)
                            throw new Exceptions.GameProtocolViolationException(context.Client, $"{MessageName(Id)} is only supported for NLS logon");

                        if (Buffer.Length < 34)
                            throw new Exceptions.GameProtocolViolationException(context.Client, $"{MessageName(Id)} buffer must be at least 34 bytes");

                        using var m = new MemoryStream(Buffer);
                        using var r = new BinaryReader(m);

                        var clientKey = r.ReadBytes(NLSServer.ValueLength);
                        var username = r.ReadString();

                        gameState.NLS = null;
                        gameState.NLSChangePassword = false;

                        if (!Battlenet.Common.AccountsDb.TryGetValue(username, out Account account) || account == null ||
                            !(account.Get(Account.NLSSaltKey, new byte[0]) is byte[] salt) || salt.Length != NLSServer.ValueLength ||
                            !(account.Get(Account.NLSVerifierKey, new byte[0]) is byte[] verifier) || verifier.Length != NLSServer.ValueLength)
                        {
                            Logging.WriteLine(Logging.LogLevel.Info, Logging.LogType.Client_Game, context.Client.RemoteEndPoint, $"Account [{username}] does not exist or has no NLS credentials");
                            return Reply(context, Statuses.DoesNotExist);
                        }

                        gameState.Username = username;
                        gameState.NLSClientKey = clientKey;
                        gameState.NLS = new NLSServer(salt, verifier);
                        gameState.NLSChangePassword = true;
                        return Reply(context, Statuses.Success, gameState.NLS.Salt, gameState.NLS.ServerKey);
                    }
                case MessageDirection.ServerToClient:
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
            }

            return false;
        }

        private static bool Reply(MessageContext context, Statuses status, byte[] salt = null, byte[] serverKey = null)
        {
            return new SID_AUTH_ACCOUNTCHANGE().Invoke(new MessageContext(context.Client, MessageDirection.ServerToClient, new Dictionary<string, object>() {{ "status", status }, { "salt", salt }, { "serverKey", serverKey }}));
        }
    }
}
