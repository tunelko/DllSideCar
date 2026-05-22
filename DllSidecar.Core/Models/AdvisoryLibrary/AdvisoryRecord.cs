namespace DllSidecar.Core.Models.AdvisoryLibrary;

public sealed class AdvisoryRecord
{
    public string Id { get; set; } = "";
    public DateTime CreatedAtUtc { get; set; }
    public DateTime UpdatedAtUtc { get; set; }
    public AdvisoryStatus Status { get; set; }

    public string Title { get; set; } = "";
    public string? Vendor { get; set; }
    public string? Product { get; set; }
    public string? ProductVersion { get; set; }
    public string? Architecture { get; set; }

    public string? PePath { get; set; }
    public string? PeFilename { get; set; }
    public string? InstallDirectory { get; set; }

    public string VulnerabilityType { get; set; } = "DLL Sideloading";
    public string CweId { get; set; } = "CWE-427";
    public string CweName { get; set; } = "Uncontrolled Search Path Element";

    public string ResearcherName { get; set; } = "";
    public string ResearcherHandle { get; set; } = "";
    public string ResearcherBlog { get; set; } = "";
    public string ResearcherEmail { get; set; } = "";

    public string? PayloadDescription { get; set; }
    public string? ImporterExe { get; set; }
    public string? GeneratedDllPath { get; set; }

    public bool DirectoryLowPrivWritable { get; set; }
    public string? WritableByPrincipals { get; set; }

    public string? CvssVector { get; set; }
    public double? CvssScore { get; set; }
    public string? CvssSeverity { get; set; }

    public string DisclosurePolicy { get; set; } = "";
    public DateTime? DiscoveredOn { get; set; }
    public DateTime? ReportedOn { get; set; }
    public DateTime? DisclosedOn { get; set; }

    public string MarkdownBody { get; set; } = "";
    public string? Notes { get; set; }

    public string? SourceScanDir { get; set; }
    public string? SourceCandidateKind { get; set; }
    public string? SourceCandidateKey { get; set; }

    public string? LastExportedMarkdownPath { get; set; }
    public string? LastExportedPdfPath { get; set; }

    // ---- Schema v4 — Template Fields persistence ----
    public string? VulnerabilityTypeText { get; set; }
    public string? VendorUrl { get; set; }
    public string? VendorPocName { get; set; }
    public string? VendorPocEmail { get; set; }
    public string? DeviceUrlReference { get; set; }
    public string? DeviceBriefSummary { get; set; }
    public string? AffectedComponents { get; set; }
    public string? PreviousRequirements { get; set; }
    public string? ProposedSolution { get; set; }
    public string? HasContactedVendorNote { get; set; }
    public string? CvssV4Vector { get; set; }
    public double? CvssV4Score { get; set; }
    public string? CvssV4Severity { get; set; }
    // Researcher-identity overrides — null means "fall back to AppConfig.Researcher at load time".
    public string? ResearcherPgpFingerprint { get; set; }
    public string? ResearcherPgpKeyId { get; set; }

    // ---- Schema v5 — active template restoration ----
    /// <summary>
    /// Renderer id ("markdown" / "ghsa") that was active the last time this advisory was saved.
    /// Restored on reopen so editing non-Markdown bodies doesn't silently revert to Markdown
    /// the moment the user touches Template Fields or the Vendor box. Null on legacy rows or
    /// when the renderer is unknown — AdvisoryPage falls back to "markdown".
    /// </summary>
    public string? LastTemplateId { get; set; }

    // ---- Schema v6 — per-vendor sequential id ----
    /// <summary>
    /// 1-based sequence number scoped to <see cref="Vendor"/>. Allocated lazily on first
    /// artifact write (or vendor change) and never reused — soft-deleted rows still hold
    /// their slot. Drives the human-readable filename pattern e.g.
    /// <c>DLL_SIDELOADING_ADVISORY_0001.txt</c>.
    /// </summary>
    public int? SequenceNumber { get; set; }

    public List<AdvisoryTimelineEvent> Timeline { get; set; } = [];
    public List<AdvisoryArtifact> Artifacts { get; set; } = [];
    public List<AdvisoryLink> Links { get; set; } = [];
}

public sealed class AdvisoryTimelineEvent
{
    public long Id { get; set; }
    public string AdvisoryId { get; set; } = "";
    public TimelineEventKind EventKind { get; set; }
    public DateTime EventAtUtc { get; set; }
    public string Title { get; set; } = "";
    public string? Note { get; set; }
    public AdvisoryStatus? OldStatus { get; set; }
    public AdvisoryStatus? NewStatus { get; set; }
}

public sealed class AdvisoryArtifact
{
    public long Id { get; set; }
    public string AdvisoryId { get; set; } = "";
    public ArtifactKind ArtifactKind { get; set; }
    public string Path { get; set; } = "";
    public string? Label { get; set; }
    public string? Sha256 { get; set; }
    public DateTime CreatedAtUtc { get; set; }
    /// <summary>
    /// Renderer that produced this artifact (e.g. "markdown", "ghsa"). Used by the Library
    /// tree to group files into format folders. Null for user-uploaded attachments that
    /// aren't tied to a template.
    /// </summary>
    public string? TemplateId { get; set; }
    /// <summary>
    /// Workflow state for THIS artifact, independent of the parent advisory's status. Each
    /// format (Markdown / GHSA) tracks its own lifecycle because submission flows differ
    /// (GHSA → GitHub, Markdown → blog) and shouldn't bleed into each other. Defaults to
    /// Draft on create.
    /// </summary>
    public AdvisoryStatus Status { get; set; } = AdvisoryStatus.Draft;
}

public sealed class AdvisoryLink
{
    public long Id { get; set; }
    public string AdvisoryId { get; set; } = "";
    public AdvisoryLinkKind LinkKind { get; set; }
    public string Value { get; set; } = "";
    public string? Label { get; set; }
}

public sealed class AdvisoryRecordListItem
{
    public string Id { get; set; } = "";
    public AdvisoryStatus Status { get; set; }
    public string Title { get; set; } = "";
    public string? Vendor { get; set; }
    public string? Product { get; set; }
    public string? ProductVersion { get; set; }
    public DateTime UpdatedAtUtc { get; set; }
    public int TimelineCount { get; set; }
}

public sealed class AdvisoryQuery
{
    public string? Search { get; set; }
    public string? Vendor { get; set; }
    public AdvisoryStatus? Status { get; set; }
    public int Limit { get; set; } = 200;
}

public sealed class AdvisoryCreateOptions
{
    public string? SourceScanDir { get; set; }
    public string? SourceCandidateKind { get; set; }
    public string? SourceCandidateKey { get; set; }
    /// <summary>Active renderer id at create time (e.g. "ghsa"). Persisted to advisory_records.last_template_id.</summary>
    public string? LastTemplateId { get; set; }
}
