namespace TlsClient;

internal sealed class ExpectContinueGate
{
    public TaskCompletionSource Continue { get; } = new(
        TaskCreationOptions.RunContinuationsAsynchronously);

    public TaskCompletionSource FinalResponse { get; } = new(
        TaskCreationOptions.RunContinuationsAsynchronously);
}
