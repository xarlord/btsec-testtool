using System.Text;
using Xunit;

namespace BtSec.WindowsBleFixture.Core.Tests;

public sealed class FixtureProtocolTests
{
    [Fact]
    public void ReadPayload_is_deterministic_and_identifies_the_fixture()
    {
        var payload = FixtureProtocol.CreateReadPayload(sequence: 7);

        Assert.Equal("BTSEC-FIXTURE;version=1;sequence=7", Encoding.UTF8.GetString(payload));
    }

    [Fact]
    public void Negative_sequence_is_rejected()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => FixtureProtocol.CreateReadPayload(sequence: -1));
    }

    [Fact]
    public void WritePayload_records_hex_and_utf8_evidence_without_claiming_a_security_result()
    {
        var record = FixtureProtocol.CreateWriteEvidence(
            payload: Encoding.UTF8.GetBytes("probe"),
            timestampUtc: new DateTimeOffset(2026, 7, 15, 12, 0, 0, TimeSpan.Zero));

        Assert.Equal("WRITE_RECEIVED", record.Kind);
        Assert.Equal("70726F6265", record.PayloadHex);
        Assert.Equal("probe", record.PayloadUtf8);
        Assert.Equal("UNCLASSIFIED", record.Assessment);
        Assert.Equal("2026-07-15T12:00:00.0000000+00:00", record.TimestampUtc.ToString("O"));
    }

    [Fact]
    public void Invalid_utf8_is_preserved_as_hex_without_a_misleading_text_value()
    {
        var record = FixtureProtocol.CreateWriteEvidence(
            payload: new byte[] { 0xFF, 0xFE },
            timestampUtc: new DateTimeOffset(2026, 7, 15, 12, 0, 0, TimeSpan.Zero));

        Assert.Equal("FFFE", record.PayloadHex);
        Assert.Null(record.PayloadUtf8);
        Assert.Equal("UNCLASSIFIED", record.Assessment);
    }
}
