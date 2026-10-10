using Atlasd.Daemon;
using System;
using System.Collections.Generic;
using System.IO;

namespace Atlasd.Battlenet.Protocols.Game.Messages
{
    class SID_AUTH_ACCOUNTCHANGEPROOF : Message
    {
        public enum Statuses : UInt32
        {
            Success = 0x00,
            BadPassword = 0x02,
        }

        public SID_AUTH_ACCOUNTCHANGEPROOF()
        {
            Id = (byte)MessageIds.SID_AUTH_ACCOUNTCHANGEPROOF;
            Buffer = new byte[0];
        }

        public SID_AUTH_ACCOUNTCHANGEPROOF(byte[] buffer)
        {
            Id = (byte)MessageIds.SID_AUTH_ACCOUNTCHANGEPROOF;
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
                         * (UINT8)[20] Old password proof
                         * (UINT8)[32] New salt
                         * (UINT8)[32] New verifier
                         */

                        Logging.WriteLine(Logging.LogLevel.Debug, Logging.LogType.Client_Game, context.Client.RemoteEndPoint, $"[{Common.DirectionToString(context.Direction)}] {MessageName(Id)} ({4 + Buffer.Length} bytes)");

                        var gameState = context.Client.GameState;

                        if (gameState.NLS == null || gameState.NLSClientKey == null || !gameState.NLSChangePassword)
                            throw new Exceptions.GameProtocolViolationException(context.Client, $"{MessageName(Id)} must follow {MessageName((byte)MessageIds.SID_AUTH_ACCOUNTCHANGE)}");

                        if (Buffer.Length < NLSServer.ProofLength + 2 * NLSServer.ValueLength)
                            throw new Exceptions.GameProtocolViolationException(context.Client, $"{MessageName(Id)} buffer must be at least {NLSServer.ProofLength + 2 * NLSServer.ValueLength} bytes");

                        var nls = gameState.NLS;
                        gameState.NLS = null;
                        gameState.NLSChangePassword = false;

                        using var m = new MemoryStream(Buffer);
                        using var r = new BinaryReader(m);

                        var clientProof = r.ReadBytes(NLSServer.ProofLength);
                        var newSalt = r.ReadBytes(NLSServer.ValueLength);
                        var newVerifier = r.ReadBytes(NLSServer.ValueLength);

                        Battlenet.Common.AccountsDb.TryGetValue(gameState.Username, out Account account);

                        if (account == null || !nls.Verify(gameState.Username, gameState.NLSClientKey, clientProof, out var serverProof))
                        {
                            Logging.WriteLine(Logging.LogLevel.Info, Logging.LogType.Client_Game, context.Client.RemoteEndPoint, $"Account [{gameState.Username}] password change failed: bad password");
                            return Reply(context, Statuses.BadPassword);
                        }

                        account.Set(Account.NLSSaltKey, newSalt);
                        account.Set(Account.NLSVerifierKey, newVerifier);

                        Logging.WriteLine(Logging.LogLevel.Info, Logging.LogType.Client_Game, context.Client.RemoteEndPoint, $"Account [{gameState.Username}] password changed");
                        return Reply(context, Statuses.Success, serverProof);
                    }
                case MessageDirection.ServerToClient:
                    {
                        /**
                         * (UINT32)    Status
                         * (UINT8)[20] Server password proof
                         */

                        var status = (Statuses)context.Arguments["status"];
                        var serverProof = context.Arguments.TryGetValue("serverProof", out var proofValue) && proofValue is byte[] proofBytes ? proofBytes : new byte[NLSServer.ProofLength];

                        Buffer = new byte[4 + NLSServer.ProofLength];

                        using var m = new MemoryStream(Buffer);
                        using var w = new BinaryWriter(m);

                        w.Write((UInt32)status);
                        w.Write(serverProof);

                        Logging.WriteLine(Logging.LogLevel.Debug, Logging.LogType.Client_Game, context.Client.RemoteEndPoint, $"[{Common.DirectionToString(context.Direction)}] {MessageName(Id)} ({4 + Buffer.Length} bytes) (status: 0x{(UInt32)status:X8})");
                        context.Client.Send(ToByteArray(context.Client.ProtocolType));
                        return true;
                    }
            }

            return false;
        }

        private static bool Reply(MessageContext context, Statuses status, byte[] serverProof = null)
        {
            return new SID_AUTH_ACCOUNTCHANGEPROOF().Invoke(new MessageContext(context.Client, MessageDirection.ServerToClient, new Dictionary<string, object>() {{ "status", status }, { "serverProof", serverProof }}));
        }
    }
}
