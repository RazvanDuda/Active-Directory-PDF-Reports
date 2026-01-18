use anyhow::Result;
use printpdf::*;
use std::io::BufWriter;
use crate::models::RightSource;
use crate::report_data::EnhancedReportData;
use crate::permission_analyzer::RiskLevel;

// Enterprise color palette
struct Colors;

impl Colors {
    // Primary colors
    const DARK_BLUE: (u8, u8, u8) = (44, 82, 130);        // #2C5282
    const LIGHT_GRAY: (u8, u8, u8) = (247, 250, 252);     // #F7FAFC
    const MEDIUM_GRAY: (u8, u8, u8) = (226, 232, 240);    // #E2E8F0
    const DARK_GRAY: (u8, u8, u8) = (113, 128, 150);      // #718096

    // Risk colors
    const CRITICAL_RED: (u8, u8, u8) = (197, 48, 48);     // #C53030
    const HIGH_ORANGE: (u8, u8, u8) = (221, 107, 32);     // #DD6B20
    const MEDIUM_YELLOW: (u8, u8, u8) = (214, 158, 46);   // #D69E2E
    const LOW_GREEN: (u8, u8, u8) = (56, 161, 105);       // #38A169

    // Status colors
    const SUCCESS_GREEN: (u8, u8, u8) = (72, 187, 120);   // #48BB78
    const WARNING_RED: (u8, u8, u8) = (245, 101, 101);    // #F56565

    fn to_rgb(color: (u8, u8, u8)) -> Color {
        Color::Rgb(Rgb::new(
            color.0 as f32 / 255.0,
            color.1 as f32 / 255.0,
            color.2 as f32 / 255.0,
            None
        ))
    }

    fn risk_color(level: &RiskLevel) -> (u8, u8, u8) {
        match level {
            RiskLevel::Critical => Self::CRITICAL_RED,
            RiskLevel::High => Self::HIGH_ORANGE,
            RiskLevel::Medium => Self::MEDIUM_YELLOW,
            RiskLevel::Low => Self::LOW_GREEN,
        }
    }
}

pub struct PdfGenerator {
    total_pages: usize,
}

impl PdfGenerator {
    pub fn new() -> Result<Self> {
        Ok(Self { total_pages: 0 })
    }

    pub fn generate_report(&mut self, data: &EnhancedReportData) -> Result<Vec<u8>> {
        // Create a PDF document in PORTRAIT orientation
        let (mut doc, page1, layer1) = PdfDocument::new(
            "Active Directory User Report",
            Mm(210.0),  // Width - portrait
            Mm(297.0),  // Height - portrait
            "Layer 1"
        );

        // Set up fonts
        let font = doc.add_builtin_font(BuiltinFont::Helvetica)?;
        let bold_font = doc.add_builtin_font(BuiltinFont::HelveticaBold)?;
        let courier = doc.add_builtin_font(BuiltinFont::Courier)?;

        let mut current_page = page1;
        let mut current_layer_index = layer1;
        let mut page_number = 1;

        // Layout constants for PORTRAIT
        let line_height = Mm(5.5);
        let left_margin = Mm(20.0);
        let right_margin = Mm(190.0);  // Narrower for portrait
        let top_margin = Mm(277.0);    // Adjusted for portrait height
        let bottom_margin = Mm(25.0);

        // Generate cover page
        self.render_cover_page(
            &mut doc,
            current_page,
            current_layer_index,
            data,
            &bold_font,
            &font,
        );

        // Continue content on same page below cover page header
        // Cover page content ends around y=234mm, start content with spacing
        let mut y_position = Mm(220.0);  // Start content 14mm below cover page content

        // Helper closure for page management
        let mut check_new_page = |doc: &mut PdfDocumentReference,
                                   y: &mut Mm,
                                   current_page: &mut PdfPageIndex,
                                   current_layer: &mut PdfLayerIndex,
                                   page_num: &mut usize,
                                   min_space: f32| {
            if y.0 < bottom_margin.0 + min_space {
                // Render footer on current page
                self.render_footer(doc, *current_page, *current_layer, &font, *page_num, data);

                // Create new page in portrait
                let (new_page, new_layer) = doc.add_page(Mm(210.0), Mm(297.0), "Layer 1");
                *current_page = new_page;
                *current_layer = new_layer;
                *page_num += 1;
                *y = top_margin;

                // Render header on new page
                self.render_header(doc, *current_page, *current_layer, &bold_font, &font);
            }
        };

        // Executive Summary
        check_new_page(&mut doc, &mut y_position, &mut current_page, &mut current_layer_index, &mut page_number, 60.0);
        y_position = self.render_executive_summary(
            &doc,
            current_page,
            current_layer_index,
            y_position,
            line_height,
            left_margin,
            data,
            &bold_font,
            &font,
        );
        y_position = y_position - line_height * 3.0;

        // User Information section
        check_new_page(&mut doc, &mut y_position, &mut current_page, &mut current_layer_index, &mut page_number, 50.0);
        y_position = self.render_section_header(
            &doc,
            current_page,
            current_layer_index,
            y_position,
            line_height,
            left_margin,
            right_margin,
            "User Information",
            &bold_font,
        );

        let user_info = vec![
            ("SAM Account Name", data.user().sam_account_name.clone()),
            ("Display Name", data.user().display_name.clone().unwrap_or("N/A".to_string())),
            ("Email", data.user().email.clone().unwrap_or("N/A".to_string())),
            ("Department", data.user().department.clone().unwrap_or("N/A".to_string())),
            ("Title", data.user().title.clone().unwrap_or("N/A".to_string())),
        ];

        for (label, value) in user_info {
            check_new_page(&mut doc, &mut y_position, &mut current_page, &mut current_layer_index, &mut page_number, 10.0);
            let current_layer = doc.get_page(current_page).get_layer(current_layer_index);
            current_layer.use_text(label, 10.0, left_margin + Mm(5.0), y_position, &bold_font);
            current_layer.use_text(&value, 10.0, left_margin + Mm(60.0), y_position, &font);
            y_position = y_position - line_height;
        }

        // Distinguished Name (needs wrapping)
        check_new_page(&mut doc, &mut y_position, &mut current_page, &mut current_layer_index, &mut page_number, 15.0);
        let current_layer = doc.get_page(current_page).get_layer(current_layer_index);
        current_layer.use_text("Distinguished Name", 10.0, left_margin + Mm(5.0), y_position, &bold_font);
        y_position = y_position - line_height;
        current_layer.use_text(&data.user().distinguished_name, 8.0, left_margin + Mm(5.0), y_position, &courier);
        y_position = y_position - line_height * 3.0;

        // Account Status section
        check_new_page(&mut doc, &mut y_position, &mut current_page, &mut current_layer_index, &mut page_number, 50.0);
        y_position = self.render_section_header(
            &doc,
            current_page,
            current_layer_index,
            y_position,
            line_height,
            left_margin,
            right_margin,
            "Account Status",
            &bold_font,
        );

        let status_items = vec![
            ("Account Enabled", data.user().account_enabled, false),
            ("Account Locked", data.user().account_locked, true),
            ("Password Expired", data.user().password_expired, true),
            ("Password Never Expires", data.user().password_never_expires, true),
        ];

        for (label, value, is_warning) in status_items {
            check_new_page(&mut doc, &mut y_position, &mut current_page, &mut current_layer_index, &mut page_number, 10.0);
            let current_layer = doc.get_page(current_page).get_layer(current_layer_index);

            current_layer.use_text(label, 10.0, left_margin + Mm(5.0), y_position, &bold_font);

            let status_text = if value { "Yes" } else { "No" };
            let status_color = if value == is_warning {
                Colors::to_rgb(Colors::WARNING_RED)
            } else {
                Colors::to_rgb(Colors::SUCCESS_GREEN)
            };

            current_layer.set_fill_color(status_color);
            current_layer.use_text(status_text, 10.0, left_margin + Mm(60.0), y_position, &bold_font);
            current_layer.set_fill_color(Color::Rgb(Rgb::new(0.0, 0.0, 0.0, None)));

            y_position = y_position - line_height;
        }

        // Timestamps
        check_new_page(&mut doc, &mut y_position, &mut current_page, &mut current_layer_index, &mut page_number, 15.0);
        let current_layer = doc.get_page(current_page).get_layer(current_layer_index);

        let created = format!("Created: {}", data.user().created.map(|d| d.format("%d-%m-%Y %H:%M:%S").to_string())
            .unwrap_or_else(|| "N/A".to_string()));
        current_layer.use_text(&created, 9.0, left_margin + Mm(5.0), y_position, &font);
        y_position = y_position - line_height;

        let last_logon = format!("Last Logon: {}", data.user().last_logon.map(|d| d.format("%d-%m-%Y %H:%M:%S").to_string())
            .unwrap_or_else(|| "Never".to_string()));
        current_layer.use_text(&last_logon, 9.0, left_margin + Mm(5.0), y_position, &font);
        y_position = y_position - line_height * 3.0;

        // Risk Assessment section
        if let Some(ref risk) = data.risk_assessment {
            check_new_page(&mut doc, &mut y_position, &mut current_page, &mut current_layer_index, &mut page_number, 70.0);
            y_position = self.render_section_header(
                &doc,
                current_page,
                current_layer_index,
                y_position,
                line_height,
                left_margin,
                right_margin,
                "Risk Assessment",
                &bold_font,
            );

            // Risk score box
            y_position = self.render_risk_score_box(
                &doc,
                current_page,
                current_layer_index,
                y_position,
                left_margin,
                risk.overall_score,
                &risk.risk_level,
                &bold_font,
                &font,
            );
            y_position = y_position - line_height * 2.0;

            // Top risk factors
            if !risk.contributing_factors.is_empty() {
                check_new_page(&mut doc, &mut y_position, &mut current_page, &mut current_layer_index, &mut page_number, 30.0);
                let current_layer = doc.get_page(current_page).get_layer(current_layer_index);
                current_layer.use_text("Top Risk Factors:", 12.0, left_margin + Mm(5.0), y_position, &bold_font);
                y_position = y_position - line_height * 1.5;

                for factor in risk.contributing_factors.iter().take(5) {
                    check_new_page(&mut doc, &mut y_position, &mut current_page, &mut current_layer_index, &mut page_number, 10.0);
                    y_position = self.render_risk_item(
                        &doc,
                        current_page,
                        current_layer_index,
                        y_position,
                        left_margin,
                        &factor.description,
                        factor.risk_contribution,
                        &font,
                    );
                }
                y_position = y_position - line_height;
            }
        }
        y_position = y_position - line_height * 2.0;

        // Group Memberships section
        check_new_page(&mut doc, &mut y_position, &mut current_page, &mut current_layer_index, &mut page_number, 50.0);
        y_position = self.render_section_header(
            &doc,
            current_page,
            current_layer_index,
            y_position,
            line_height,
            left_margin,
            right_margin,
            "Group Memberships",
            &bold_font,
        );

        if let Some(primary) = &data.user().primary_group {
            check_new_page(&mut doc, &mut y_position, &mut current_page, &mut current_layer_index, &mut page_number, 10.0);
            let current_layer = doc.get_page(current_page).get_layer(current_layer_index);
            let primary_text = format!("Primary Group: {}", primary.name);
            current_layer.use_text(&primary_text, 10.0, left_margin + Mm(5.0), y_position, &bold_font);
            y_position = y_position - line_height * 1.5;
        }

        let total_groups = data.user().groups.len();
        let total_nested: usize = data.user().groups.iter()
            .map(|g| g.nested_groups.len())
            .sum();

        check_new_page(&mut doc, &mut y_position, &mut current_page, &mut current_layer_index, &mut page_number, 10.0);
        let current_layer = doc.get_page(current_page).get_layer(current_layer_index);
        let groups_summary = format!("Direct Groups: {} | Nested Groups: {}", total_groups, total_nested);
        current_layer.use_text(&groups_summary, 10.0, left_margin + Mm(5.0), y_position, &font);
        y_position = y_position - line_height * 1.5;

        if !data.user().groups.is_empty() {
            for group in &data.user().groups {
                check_new_page(&mut doc, &mut y_position, &mut current_page, &mut current_layer_index, &mut page_number, 10.0);
                let current_layer = doc.get_page(current_page).get_layer(current_layer_index);

                let group_info = format!("• {} ({:?}, {:?})", group.name, group.group_type, group.scope);
                current_layer.use_text(&group_info, 9.0, left_margin + Mm(7.0), y_position, &font);
                y_position = y_position - line_height;

                // Add nested groups
                for nested in &group.nested_groups {
                    check_new_page(&mut doc, &mut y_position, &mut current_page, &mut current_layer_index, &mut page_number, 10.0);
                    let current_layer = doc.get_page(current_page).get_layer(current_layer_index);

                    let nested_info = format!("  └─ {} ({:?}, {:?})", nested.name, nested.group_type, nested.scope);
                    current_layer.use_text(&nested_info, 8.0, left_margin + Mm(12.0), y_position, &font);
                    y_position = y_position - line_height * 0.9;
                }
            }
        }
        y_position = y_position - line_height * 2.0;

        // Render footer on last page
        self.render_footer(&doc, current_page, current_layer_index, &font, page_number, data);

        // Save to bytes
        let mut buffer = Vec::new();
        doc.save(&mut BufWriter::new(&mut buffer))?;

        Ok(buffer)
    }

    fn render_cover_page(
        &self,
        doc: &PdfDocumentReference,
        page: PdfPageIndex,
        layer: PdfLayerIndex,
        data: &EnhancedReportData,
        bold_font: &IndirectFontRef,
        font: &IndirectFontRef,
    ) {
        let current_layer = doc.get_page(page).get_layer(layer);

        // Classification badge - top margin ~20mm
        current_layer.set_fill_color(Colors::to_rgb(Colors::CRITICAL_RED));
        current_layer.use_text("CONFIDENTIAL", 12.0, Mm(20.0), Mm(275.0), bold_font);
        current_layer.set_fill_color(Color::Rgb(Rgb::new(0.0, 0.0, 0.0, None)));

        // Title section
        current_layer.set_fill_color(Colors::to_rgb(Colors::DARK_BLUE));
        current_layer.use_text("ACTIVE DIRECTORY USER ACCESS REPORT", 16.0, Mm(20.0), Mm(265.0), bold_font);
        current_layer.set_fill_color(Color::Rgb(Rgb::new(0.0, 0.0, 0.0, None)));

        // Content section - compact layout starting below title
        let content_y = Mm(250.0);  // Start content 15mm below title

        let user_display = data.user().display_name.as_ref()
            .unwrap_or(&data.user().sam_account_name);

        // Subject user section
        current_layer.use_text("Subject User:", 10.0, Mm(20.0), content_y, bold_font);
        current_layer.set_fill_color(Colors::to_rgb(Colors::DARK_BLUE));
        current_layer.use_text(user_display, 13.0, Mm(20.0), content_y - Mm(6.0), bold_font);
        current_layer.set_fill_color(Color::Rgb(Rgb::new(0.0, 0.0, 0.0, None)));

        current_layer.use_text("Account:", 9.0, Mm(20.0), content_y - Mm(12.0), font);
        current_layer.use_text(&data.user().sam_account_name, 9.0, Mm(20.0), content_y - Mm(16.0), font);

        // Report metadata section - positioned next to user info
        let meta_y = content_y;

        current_layer.use_text("Report Details", 10.0, Mm(100.0), meta_y, bold_font);

        let generated = format!("Generated: {}", data.generation_time().format("%d-%m-%Y %H:%M:%S UTC"));
        current_layer.use_text(&generated, 8.0, Mm(100.0), meta_y - Mm(5.0), font);

        let dc = format!("Domain Controller: {}", data.domain_controller());
        current_layer.use_text(&dc, 8.0, Mm(100.0), meta_y - Mm(9.0), font);

        let domain = format!("Domain: {}", data.domain_name());
        current_layer.use_text(&domain, 8.0, Mm(100.0), meta_y - Mm(13.0), font);

        // Footer notice - centered (approximate text width compensation)
        current_layer.set_fill_color(Colors::to_rgb(Colors::DARK_GRAY));
        current_layer.use_text("This report contains sensitive security information.", 8.0, Mm(38.0), Mm(20.0), font);
        current_layer.use_text("Handle according to your organization's data classification policy.", 8.0, Mm(25.0), Mm(15.0), font);
        current_layer.set_fill_color(Color::Rgb(Rgb::new(0.0, 0.0, 0.0, None)));
    }

    fn render_header(
        &self,
        _doc: &PdfDocumentReference,
        _page: PdfPageIndex,
        _layer: PdfLayerIndex,
        _bold_font: &IndirectFontRef,
        _font: &IndirectFontRef,
    ) {
        // No header line - clean minimal design
    }

    fn render_footer(
        &self,
        doc: &PdfDocumentReference,
        page: PdfPageIndex,
        layer: PdfLayerIndex,
        font: &IndirectFontRef,
        page_number: usize,
        data: &EnhancedReportData,
    ) {
        let current_layer = doc.get_page(page).get_layer(layer);

        // Footer text (no line)
        current_layer.set_fill_color(Colors::to_rgb(Colors::DARK_GRAY));

        let page_text = format!("Page {}", page_number);
        current_layer.use_text(&page_text, 8.0, Mm(20.0), Mm(13.0), font);

        let footer = format!("{} | {}", data.domain_controller(), data.domain_name());
        current_layer.use_text(&footer, 8.0, Mm(65.0), Mm(13.0), font);

        let timestamp = data.generation_time().format("%d-%m-%Y %H:%M").to_string();
        current_layer.use_text(&timestamp, 8.0, Mm(165.0), Mm(13.0), font);

        current_layer.set_fill_color(Color::Rgb(Rgb::new(0.0, 0.0, 0.0, None)));
    }

    fn render_executive_summary(
        &self,
        doc: &PdfDocumentReference,
        page: PdfPageIndex,
        layer: PdfLayerIndex,
        mut y_position: Mm,
        line_height: Mm,
        left_margin: Mm,
        data: &EnhancedReportData,
        bold_font: &IndirectFontRef,
        font: &IndirectFontRef,
    ) -> Mm {
        let current_layer = doc.get_page(page).get_layer(layer);

        // Section header
        current_layer.set_fill_color(Colors::to_rgb(Colors::DARK_BLUE));
        current_layer.use_text("EXECUTIVE SUMMARY", 16.0, left_margin, y_position, bold_font);
        current_layer.set_fill_color(Color::Rgb(Rgb::new(0.0, 0.0, 0.0, None)));
        y_position = y_position - line_height * 2.5;

        // Metrics boxes - narrower for portrait
        let box_width = Mm(50.0);  // Narrower boxes for portrait
        let box_height = Mm(22.0);
        let spacing = Mm(5.0);    // Less spacing

        // Total Groups
        let x1 = left_margin + Mm(10.0);
        self.draw_rectangle(doc, page, layer, x1, y_position - box_height, box_width, box_height, Colors::LIGHT_GRAY);
        current_layer.use_text("Direct Groups", 10.0, x1 + Mm(3.0), y_position - Mm(6.0), font);
        let group_count = data.user().groups.len().to_string();
        current_layer.set_fill_color(Colors::to_rgb(Colors::DARK_BLUE));
        current_layer.use_text(&group_count, 20.0, x1 + Mm(3.0), y_position - Mm(16.0), bold_font);
        current_layer.set_fill_color(Color::Rgb(Rgb::new(0.0, 0.0, 0.0, None)));

        // Nested Groups
        let x2 = x1 + box_width + spacing;
        self.draw_rectangle(doc, page, layer, x2, y_position - box_height, box_width, box_height, Colors::LIGHT_GRAY);
        current_layer.use_text("Nested Groups", 10.0, x2 + Mm(3.0), y_position - Mm(6.0), font);
        let nested_count: usize = data.user().groups.iter().map(|g| g.nested_groups.len()).sum();
        let nested_str = nested_count.to_string();
        current_layer.set_fill_color(Colors::to_rgb(Colors::DARK_BLUE));
        current_layer.use_text(&nested_str, 20.0, x2 + Mm(3.0), y_position - Mm(16.0), bold_font);
        current_layer.set_fill_color(Color::Rgb(Rgb::new(0.0, 0.0, 0.0, None)));

        // Risk Score
        if let Some(ref risk) = data.risk_assessment {
            let x3 = x2 + box_width + spacing;
            let risk_color = Colors::risk_color(&risk.risk_level);
            self.draw_rectangle(doc, page, layer, x3, y_position - box_height, box_width, box_height, risk_color);

            current_layer.set_fill_color(Color::Rgb(Rgb::new(1.0, 1.0, 1.0, None)));
            current_layer.use_text("Risk Score", 10.0, x3 + Mm(3.0), y_position - Mm(6.0), bold_font);
            let risk_str = format!("{}/100", risk.overall_score);
            current_layer.use_text(&risk_str, 18.0, x3 + Mm(3.0), y_position - Mm(16.0), bold_font);
            current_layer.set_fill_color(Color::Rgb(Rgb::new(0.0, 0.0, 0.0, None)));
        }

        y_position - box_height - line_height
    }

    fn render_section_header(
        &self,
        _doc: &PdfDocumentReference,
        page: PdfPageIndex,
        layer: PdfLayerIndex,
        y_position: Mm,
        line_height: Mm,
        left_margin: Mm,
        _right_margin: Mm,
        title: &str,
        bold_font: &IndirectFontRef,
    ) -> Mm {
        let current_layer = _doc.get_page(page).get_layer(layer);

        // Section title (no underline)
        current_layer.set_fill_color(Colors::to_rgb(Colors::DARK_BLUE));
        current_layer.use_text(title, 14.0, left_margin, y_position, bold_font);
        current_layer.set_fill_color(Color::Rgb(Rgb::new(0.0, 0.0, 0.0, None)));

        y_position - line_height * 2.0
    }

    fn render_risk_score_box(
        &self,
        doc: &PdfDocumentReference,
        page: PdfPageIndex,
        layer: PdfLayerIndex,
        y_position: Mm,
        left_margin: Mm,
        score: u8,
        risk_level: &RiskLevel,
        bold_font: &IndirectFontRef,
        font: &IndirectFontRef,
    ) -> Mm {
        let current_layer = doc.get_page(page).get_layer(layer);

        let risk_color = Colors::risk_color(risk_level);

        // Compact text-only layout (no background box)
        current_layer.set_fill_color(Colors::to_rgb(Colors::DARK_BLUE));
        current_layer.use_text("OVERALL RISK SCORE", 12.0, left_margin + Mm(5.0), y_position, bold_font);
        current_layer.set_fill_color(Color::Rgb(Rgb::new(0.0, 0.0, 0.0, None)));

        let score_text = format!("{}/100", score);
        current_layer.set_fill_color(Colors::to_rgb(risk_color));
        current_layer.use_text(&score_text, 20.0, left_margin + Mm(5.0), y_position - Mm(8.0), bold_font);

        let level_text = format!("{:?} RISK", risk_level).to_uppercase();
        current_layer.use_text(&level_text, 14.0, left_margin + Mm(35.0), y_position - Mm(7.0), bold_font);
        current_layer.set_fill_color(Color::Rgb(Rgb::new(0.0, 0.0, 0.0, None)));

        y_position - Mm(12.0)
    }

    fn render_risk_item(
        &self,
        doc: &PdfDocumentReference,
        page: PdfPageIndex,
        layer: PdfLayerIndex,
        y_position: Mm,
        left_margin: Mm,
        description: &str,
        risk_value: u8,
        font: &IndirectFontRef,
    ) -> Mm {
        let current_layer = doc.get_page(page).get_layer(layer);

        // Risk indicator square
        let indicator_color = if risk_value >= 75 {
            Colors::CRITICAL_RED
        } else if risk_value >= 50 {
            Colors::HIGH_ORANGE
        } else if risk_value >= 25 {
            Colors::MEDIUM_YELLOW
        } else {
            Colors::LOW_GREEN
        };

        self.draw_rectangle(doc, page, layer, left_margin + Mm(7.0), y_position - Mm(1.0), Mm(3.0), Mm(3.0), indicator_color);

        // Description
        current_layer.use_text(description, 9.0, left_margin + Mm(12.0), y_position, font);

        // Risk value
        let risk_text = format!("(Risk: {}/100)", risk_value);
        current_layer.set_fill_color(Colors::to_rgb(Colors::DARK_GRAY));
        current_layer.use_text(&risk_text, 8.0, left_margin + Mm(12.0), y_position - Mm(4.0), font);
        current_layer.set_fill_color(Color::Rgb(Rgb::new(0.0, 0.0, 0.0, None)));

        y_position - Mm(8.0)
    }

    fn draw_rectangle(
        &self,
        _doc: &PdfDocumentReference,
        _page: PdfPageIndex,
        _layer: PdfLayerIndex,
        _x: Mm,
        _y: Mm,
        _width: Mm,
        _height: Mm,
        _color: (u8, u8, u8),
    ) {
        // Simplified - using text-based visual elements instead
        // Complex shape drawing requires deeper printpdf API integration
    }

    fn draw_line(
        &self,
        doc: &PdfDocumentReference,
        page: PdfPageIndex,
        layer: PdfLayerIndex,
        x1: Mm,
        y1: Mm,
        x2: Mm,
        y2: Mm,
        color: (u8, u8, u8),
        width: f32,
    ) {
        let current_layer = doc.get_page(page).get_layer(layer);

        let points = vec![
            (Point::new(x1, y1), false),
            (Point::new(x2, y2), false),
        ];

        let stroke_color = Colors::to_rgb(color);
        let line = Line {
            points,
            is_closed: false,
        };

        current_layer.set_outline_color(stroke_color);
        current_layer.set_outline_thickness(width);
        current_layer.add_line(line);
    }
}
