namespace DllSidecar.Core.Models.AdvisoryLibrary;

public enum AdvisoryStatus
{
    Draft = 0,
    ReadyToReport = 1,
    SentToVendor = 2,
    Acknowledged = 3,
    CveRequested = 4,
    CveAssigned = 5,
    Fixed = 6,
    Public = 7,
    Closed = 8,
    Rejected = 9,
}

public enum TimelineEventKind
{
    Created = 0,
    Edited = 1,
    ExportedMarkdown = 2,
    ExportedPdf = 3,
    VendorContacted = 4,
    VendorAcknowledged = 5,
    CveRequested = 6,
    CveAssigned = 7,
    PublicDisclosure = 8,
    StatusChanged = 9,
    Imported = 10,
    Note = 11,
}

public enum ArtifactKind
{
    Markdown = 0,
    Html = 1,
    Pdf = 2,
    Attachment = 3,
}

public enum AdvisoryLinkKind
{
    Cve = 0,
    Dll = 1,
    Path = 2,
    Reference = 3,
    VendorTicket = 4,
}
