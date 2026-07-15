using System.Text;

namespace BtSec.WindowsBleFixture.Core;

/// <summary>
/// Deterministic, test-only GATT payload and evidence helpers.
/// These records describe fixture interaction only; they never infer a vulnerability result.
/// </summary>
public static class FixtureProtocol
{
    public const string ServiceUuid = "b7ec0001-6e7f-4a55-95d1-4e1e6d4f0001";
    public const string ReadCharacteristicUuid = "b7ec0002-6e7f-4a55-95d1-4e1e6d4f0001";
    public const string WriteCharacteristicUuid = "b7ec0003-6e7f-4a55-95d1-4e1e6d4f0001";
    public const string NotifyCharacteristicUuid = "b7ec0004-6e7f-4a55-95d1-4e1e6d4f0001";

    public static byte[] CreateReadPayload(int sequence)
    {
        if (sequence < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(sequence));
        }

        return Encoding.UTF8.GetBytes($"BTSEC-FIXTURE;version=1;sequence={sequence}");
    }

    public static FixtureEvidence CreateWriteEvidence(byte[] payload, DateTimeOffset timestampUtc)
    {
        ArgumentNullException.ThrowIfNull(payload);

        return new FixtureEvidence(
            Kind: "WRITE_RECEIVED",
            PayloadHex: Convert.ToHexString(payload),
            PayloadUtf8: TryDecodeUtf8(payload),
            Assessment: "UNCLASSIFIED",
            TimestampUtc: timestampUtc.ToUniversalTime());
    }

    private static string? TryDecodeUtf8(byte[] payload)
    {
        try
        {
            return new UTF8Encoding(encoderShouldEmitUTF8Identifier: false, throwOnInvalidBytes: true)
                .GetString(payload);
        }
        catch (DecoderFallbackException)
        {
            return null;
        }
    }
}

public sealed record FixtureEvidence(
    string Kind,
    string PayloadHex,
    string? PayloadUtf8,
    string Assessment,
    DateTimeOffset TimestampUtc);
