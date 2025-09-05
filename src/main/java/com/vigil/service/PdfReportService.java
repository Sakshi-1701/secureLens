package com.vigil.service;

import com.itextpdf.html2pdf.HtmlConverter;
import com.itextpdf.html2pdf.resolver.font.DefaultFontProvider;
import com.itextpdf.kernel.colors.ColorConstants;
import com.itextpdf.kernel.colors.DeviceRgb;
import com.itextpdf.kernel.pdf.PdfDocument;
import com.itextpdf.kernel.pdf.PdfWriter;
import com.itextpdf.layout.Document;
import com.itextpdf.layout.element.Div;
import com.itextpdf.layout.element.Paragraph;
import com.itextpdf.layout.element.Table;
import com.itextpdf.layout.element.Text;
import com.itextpdf.layout.properties.BorderRadius;
import com.itextpdf.layout.properties.HorizontalAlignment;
import com.itextpdf.layout.properties.TextAlignment;
import com.itextpdf.layout.properties.UnitValue;
import com.vigil.domain.Plugin;
import com.vigil.domain.ScanResult;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.time.format.DateTimeFormatter;
import java.util.List;

@Service
@RequiredArgsConstructor
@Slf4j
public class PdfReportService {

    public byte[] generatePdfReport(Plugin plugin, List<ScanResult> vulnerabilities) {
        log.info("Generating PDF report for plugin: {} with {} vulnerabilities", 
                plugin.getPluginName(), vulnerabilities.size());
        
        try (ByteArrayOutputStream outputStream = new ByteArrayOutputStream()) {
            PdfWriter writer = new PdfWriter(outputStream);
            PdfDocument pdfDoc = new PdfDocument(writer);
            Document document = new Document(pdfDoc);
            
            // Add title
            Paragraph title = new Paragraph("Vigil Security Scan Report")
                    .setTextAlignment(TextAlignment.CENTER)
                    .setFontSize(24)
                    .setBold()
                    .setMarginBottom(20);
            document.add(title);
            
            // Add plugin metadata card
            addPluginMetadataCard(document, plugin, vulnerabilities);
            
            // Add vulnerabilities table
            addVulnerabilitiesTable(document, vulnerabilities);
            
            document.close();
            
            byte[] pdfBytes = outputStream.toByteArray();
            log.info("PDF report generated successfully, size: {} bytes", pdfBytes.length);
            return pdfBytes;
            
        } catch (IOException e) {
            log.error("Failed to generate PDF report", e);
            throw new RuntimeException("Failed to generate PDF report", e);
        }
    }

    private void addPluginMetadataCard(Document document, Plugin plugin, List<ScanResult> vulnerabilities) {
        // Create a card-like container
        Div card = new Div()
                .setBackgroundColor(ColorConstants.LIGHT_GRAY, 0.1f)
                .setPadding(20)
                .setMarginBottom(20)
                .setBorderRadius(new BorderRadius(8));
        
        // Plugin name
        Paragraph pluginName = new Paragraph("Plugin: " + plugin.getPluginName())
                .setFontSize(18)
                .setBold()
                .setMarginBottom(10);
        card.add(pluginName);
        
        // Metadata table
        Table metadataTable = new Table(2).setWidth(UnitValue.createPercentValue(100));
        
        metadataTable.addCell(createMetadataCell("Plugin ID", true));
        metadataTable.addCell(createMetadataCell(plugin.getId().toString(), false));
        
        metadataTable.addCell(createMetadataCell("Scan Date", true));
        metadataTable.addCell(createMetadataCell(
                plugin.getUploadTimestamp().format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss")), false));
        
        metadataTable.addCell(createMetadataCell("Source Type", true));
        metadataTable.addCell(createMetadataCell(plugin.getSourceType(), false));
        
        metadataTable.addCell(createMetadataCell("Scan Status", true));
        metadataTable.addCell(createMetadataCell(plugin.getScanStatus(), false));
        
        metadataTable.addCell(createMetadataCell("Total Vulnerabilities", true));
        metadataTable.addCell(createMetadataCell(String.valueOf(vulnerabilities.size()), false));
        
        // Count by severity
        long highCount = vulnerabilities.stream().filter(v -> "HIGH".equals(v.getSeverity())).count();
        long mediumCount = vulnerabilities.stream().filter(v -> "MEDIUM".equals(v.getSeverity())).count();
        long lowCount = vulnerabilities.stream().filter(v -> "LOW".equals(v.getSeverity())).count();
        long infoCount = vulnerabilities.stream().filter(v -> "INFO".equals(v.getSeverity())).count();
        
        metadataTable.addCell(createMetadataCell("High Severity", true));
        metadataTable.addCell(createMetadataCell(String.valueOf(highCount), false));
        
        metadataTable.addCell(createMetadataCell("Medium Severity", true));
        metadataTable.addCell(createMetadataCell(String.valueOf(mediumCount), false));
        
        metadataTable.addCell(createMetadataCell("Low Severity", true));
        metadataTable.addCell(createMetadataCell(String.valueOf(lowCount), false));
        
        metadataTable.addCell(createMetadataCell("Info Severity", true));
        metadataTable.addCell(createMetadataCell(String.valueOf(infoCount), false));
        
        card.add(metadataTable);
        document.add(card);
    }

    private com.itextpdf.layout.element.Cell createMetadataCell(String text, boolean isHeader) {
        com.itextpdf.layout.element.Cell cell = new com.itextpdf.layout.element.Cell()
                .setPadding(8)
                .setBorder(null);
        
        if (isHeader) {
            cell.add(new Paragraph(text).setBold().setFontSize(12));
        } else {
            cell.add(new Paragraph(text).setFontSize(12));
        }
        
        return cell;
    }

    private void addVulnerabilitiesTable(Document document, List<ScanResult> vulnerabilities) {
        if (vulnerabilities.isEmpty()) {
            Paragraph noVulns = new Paragraph("No vulnerabilities found")
                    .setTextAlignment(TextAlignment.CENTER)
                    .setFontSize(16)
                    .setItalic()
                    .setMarginTop(20);
            document.add(noVulns);
            return;
        }
        
        // Table title
        Paragraph tableTitle = new Paragraph("Vulnerability Details")
                .setFontSize(18)
                .setBold()
                .setMarginTop(20)
                .setMarginBottom(10);
        document.add(tableTitle);
        
        // Create table with 4 columns
        Table table = new Table(4).setWidth(UnitValue.createPercentValue(100));
        
        // Header row
        table.addHeaderCell(createHeaderCell("Vulnerability ID"));
        table.addHeaderCell(createHeaderCell("Description"));
        table.addHeaderCell(createHeaderCell("Severity"));
        table.addHeaderCell(createHeaderCell("Suggested Fix"));
        
        // Data rows
        for (ScanResult vuln : vulnerabilities) {
            table.addCell(createDataCell(vuln.getVulnerabilityId()));
            table.addCell(createDataCell(vuln.getDescription()));
            table.addCell(createSeverityCell(vuln.getSeverity()));
            table.addCell(createDataCell(vuln.getFixSuggestion()));
        }
        
        document.add(table);
    }

    private com.itextpdf.layout.element.Cell createHeaderCell(String text) {
        // Create subtle red color (RGB: 180, 30, 30) for background
        DeviceRgb subtleRed = new DeviceRgb(180, 30, 30);
        
        return new com.itextpdf.layout.element.Cell()
                .add(new Paragraph(text).setBold().setFontSize(12).setFontColor(ColorConstants.BLACK))
                .setBackgroundColor(subtleRed)
                .setPadding(10)
                .setTextAlignment(TextAlignment.CENTER);
    }

    private com.itextpdf.layout.element.Cell createDataCell(String text) {
        return new com.itextpdf.layout.element.Cell()
                .add(new Paragraph(text != null ? text : "").setFontSize(10))
                .setPadding(8)
                .setVerticalAlignment(com.itextpdf.layout.properties.VerticalAlignment.TOP);
    }

    private com.itextpdf.layout.element.Cell createSeverityCell(String severity) {
        com.itextpdf.layout.element.Cell cell = new com.itextpdf.layout.element.Cell()
                .setPadding(8)
                .setTextAlignment(TextAlignment.CENTER)
                .setVerticalAlignment(com.itextpdf.layout.properties.VerticalAlignment.MIDDLE);
        
        Text severityText = new Text(severity != null ? severity : "UNKNOWN")
                .setBold()
                .setFontSize(10);
        
        // Color code based on severity
        switch (severity != null ? severity.toUpperCase() : "") {
            case "HIGH":
                severityText.setFontColor(ColorConstants.RED);
                break;
            case "MEDIUM":
                severityText.setFontColor(ColorConstants.ORANGE);
                break;
            case "LOW":
                severityText.setFontColor(ColorConstants.YELLOW);
                break;
            case "INFO":
                severityText.setFontColor(ColorConstants.BLUE);
                break;
            default:
                severityText.setFontColor(ColorConstants.GRAY);
                break;
        }
        
        cell.add(new Paragraph(severityText));
        return cell;
    }
}
