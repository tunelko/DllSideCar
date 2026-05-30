using System.IO;
using Markdig;
using Markdig.Extensions.Tables;
using Markdig.Syntax;
using Markdig.Syntax.Inlines;
using QuestPDF.Fluent;
using QuestPDF.Helpers;
using QuestPDF.Infrastructure;

namespace DllSidecar.GUI.Services;

/// <summary>Markdown to PDF renderer built on QuestPDF + Markdig AST walking.</summary>
public static class MarkdownPdfRenderer
{
    private static readonly MarkdownPipeline Pipeline = new MarkdownPipelineBuilder()
        .UseAdvancedExtensions()
        .UsePipeTables()
        .UseAutoLinks()
        .Build();

    /// <summary>Render markdown source to a PDF on disk. Caller owns the output path.</summary>
    public static void Render(string markdown, string title, string outputPdfPath)
    {
        var doc = Markdown.Parse(markdown ?? "", Pipeline);

        Document.Create(container =>
        {
            container.Page(page =>
            {
                page.Size(PageSizes.A4);
                page.Margin(40);
                page.DefaultTextStyle(t => t
                    .FontFamily(Fonts.Calibri)
                    .FontSize(11)
                    .LineHeight(1.4f)
                    .FontColor(Colors.Grey.Darken4));

                page.Header().Column(col =>
                {
                    col.Item().Text(title).FontSize(16).Bold().FontColor(Colors.Grey.Darken4);
                    col.Item().PaddingTop(2).LineHorizontal(0.6f).LineColor(Colors.Grey.Lighten1);
                });

                page.Content().PaddingTop(10).Column(col =>
                {
                    col.Spacing(8);
                    foreach (var block in doc)
                        RenderBlock(col, block);
                });

                page.Footer().AlignCenter().Text(t =>
                {
                    t.DefaultTextStyle(s => s.FontSize(8).FontColor(Colors.Grey.Medium));
                    t.Span("Page ");
                    t.CurrentPageNumber();
                    t.Span(" / ");
                    t.TotalPages();
                });
            });
        })
        .GeneratePdf(outputPdfPath);
    }

    // ───────────────────────── Block dispatch ─────────────────────────

    private static void RenderBlock(ColumnDescriptor col, Block block)
    {
        switch (block)
        {
            case HeadingBlock h:        RenderHeading(col, h); break;
            case ParagraphBlock p:      RenderParagraph(col, p); break;
            case ListBlock l:           RenderList(col, l); break;
            case FencedCodeBlock fc:    RenderCode(col, fc); break;
            case CodeBlock cb:          RenderCode(col, cb); break;
            case QuoteBlock qb:         RenderQuote(col, qb); break;
            case ThematicBreakBlock:    col.Item().PaddingVertical(4).LineHorizontal(0.4f).LineColor(Colors.Grey.Lighten1); break;
            case Table tb:              RenderTable(col, tb); break;
            case HtmlBlock hb:          RenderHtmlBlock(col, hb); break;
            default:
                // Unknown block — surface raw content rather than dropping silently.
                var raw = block.ToString();
                if (!string.IsNullOrWhiteSpace(raw))
                    col.Item().Text(raw).FontSize(9).Italic().FontColor(Colors.Grey.Medium);
                break;
        }
    }

    private static void RenderHeading(ColumnDescriptor col, HeadingBlock h)
    {
        var size = h.Level switch
        {
            1 => 20f,
            2 => 16f,
            3 => 13f,
            4 => 12f,
            _ => 11f,
        };
        var item = col.Item().PaddingTop(h.Level == 1 ? 0 : 6);
        item.Text(t =>
        {
            t.DefaultTextStyle(s => s.FontSize(size).Bold().FontColor(Colors.Grey.Darken4));
            if (h.Inline != null) RenderInlines(t, h.Inline);
        });
        if (h.Level == 1)
            col.Item().PaddingTop(2).LineHorizontal(0.5f).LineColor(Colors.Grey.Lighten2);
    }

    private static void RenderParagraph(ColumnDescriptor col, ParagraphBlock p)
    {
        col.Item().Text(t =>
        {
            if (p.Inline != null) RenderInlines(t, p.Inline);
        });
    }

    private static void RenderList(ColumnDescriptor col, ListBlock list)
    {
        var index = 1;
        foreach (var child in list)
        {
            if (child is not ListItemBlock item) continue;
            var marker = list.IsOrdered ? $"{index}." : "•";
            index++;

            col.Item().Row(row =>
            {
                row.ConstantItem(20).PaddingLeft(6).Text(marker).FontSize(11);
                row.RelativeItem().Column(itemCol =>
                {
                    foreach (var sub in item)
                        RenderBlock(itemCol, sub);
                });
            });
        }
    }

    private static void RenderCode(ColumnDescriptor col, LeafBlock code)
    {
        var content = code.Lines.ToString();
        if (string.IsNullOrEmpty(content)) return;
        col.Item()
            .Background(Colors.Grey.Lighten4)
            .Border(0.5f).BorderColor(Colors.Grey.Lighten1)
            .Padding(8)
            .Text(content)
                .FontFamily(Fonts.Consolas)
                .FontSize(9.5f)
                .FontColor(Colors.Grey.Darken3);
    }

    private static void RenderQuote(ColumnDescriptor col, QuoteBlock quote)
    {
        col.Item()
            .BorderLeft(3)
            .BorderColor("#F39C12")
            .Background("#FFF8E6")
            .PaddingLeft(10).PaddingVertical(4)
            .Column(inner =>
            {
                inner.Spacing(4);
                foreach (var sub in quote)
                    RenderBlock(inner, sub);
            });
    }

    private static void RenderTable(ColumnDescriptor col, Table tb)
    {
        // Derive column count from widest row so partial tables still render.
        var rows = tb.OfType<TableRow>().ToList();
        if (rows.Count == 0) return;
        var columnCount = rows.Max(r => r.Count);
        if (columnCount == 0) return;

        col.Item().Table(table =>
        {
            table.ColumnsDefinition(cols =>
            {
                for (var i = 0; i < columnCount; i++) cols.RelativeColumn();
            });

            for (var r = 0; r < rows.Count; r++)
            {
                var row = rows[r];
                var isHeader = r == 0 && row.IsHeader;
                for (var c = 0; c < columnCount; c++)
                {
                    var cell = c < row.Count ? row[c] as TableCell : null;
                    var container = table.Cell()
                        .Border(0.4f).BorderColor(Colors.Grey.Lighten1)
                        .Padding(4)
                        .Background(isHeader ? Colors.Grey.Lighten3 : Colors.White);
                    container.Text(t =>
                    {
                        t.DefaultTextStyle(s => isHeader ? s.Bold() : s);
                        if (cell != null)
                            foreach (var sub in cell)
                                if (sub is ParagraphBlock pp && pp.Inline != null)
                                    RenderInlines(t, pp.Inline);
                    });
                }
            }
        });
    }

    private static void RenderHtmlBlock(ColumnDescriptor col, HtmlBlock hb)
    {
        // Surface as preformatted text with tags stripped.
        var raw = hb.Lines.ToString();
        if (string.IsNullOrWhiteSpace(raw)) return;
        var stripped = System.Text.RegularExpressions.Regex.Replace(raw, "<[^>]+>", " ").Trim();
        if (stripped.Length == 0) return;
        col.Item().Text(stripped).FontSize(11);
    }

    // ───────────────────────── Inline dispatch ─────────────────────────

    private static void RenderInlines(TextDescriptor t, ContainerInline container)
    {
        foreach (var inline in container)
            RenderInline(t, inline);
    }

    private static void RenderInline(TextDescriptor t, Inline inline)
    {
        switch (inline)
        {
            case LiteralInline lit:
                t.Span(lit.Content.ToString());
                break;

            case EmphasisInline emp:
                // DelimiterCount: 1 = italic, 2 = bold, 3 = bold-italic.
                foreach (var child in emp)
                    RenderInline(t, child, bold: emp.DelimiterCount >= 2, italic: emp.DelimiterCount % 2 == 1);
                break;

            case CodeInline code:
                t.Span(code.Content).FontFamily(Fonts.Consolas).FontSize(9.5f)
                 .BackgroundColor(Colors.Grey.Lighten4).FontColor("#B00020");
                break;

            case LinkInline link:
                {
                    var text = LinkText(link);
                    var url = link.Url ?? "";
                    var span = t.Hyperlink(text, url);
                    span.FontColor("#0A72EF").Underline();
                }
                break;

            case LineBreakInline:
                t.Line("");
                break;

            case ContainerInline cont:
                foreach (var child in cont) RenderInline(t, child);
                break;
        }
    }

    private static void RenderInline(TextDescriptor t, Inline inline, bool bold, bool italic)
    {
        switch (inline)
        {
            case LiteralInline lit:
                var span = t.Span(lit.Content.ToString());
                if (bold) span.Bold();
                if (italic) span.Italic();
                break;

            case CodeInline code:
                t.Span(code.Content).FontFamily(Fonts.Consolas).FontSize(9.5f)
                 .BackgroundColor(Colors.Grey.Lighten4).FontColor("#B00020");
                break;

            case EmphasisInline emp:
                // Compose styles when emphasis nests
                foreach (var child in emp)
                    RenderInline(t, child,
                        bold: bold || emp.DelimiterCount >= 2,
                        italic: italic || (emp.DelimiterCount % 2 == 1));
                break;

            case ContainerInline cont:
                foreach (var child in cont)
                    RenderInline(t, child, bold, italic);
                break;

            default:
                RenderInline(t, inline);
                break;
        }
    }

    private static string LinkText(LinkInline link)
    {
        var sb = new System.Text.StringBuilder();
        foreach (var child in link)
            if (child is LiteralInline lit) sb.Append(lit.Content);
        return sb.Length > 0 ? sb.ToString() : link.Url ?? "";
    }
}
