/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef TRAFFIC_TABLE_DIALOG_H
#define TRAFFIC_TABLE_DIALOG_H

#include <config.h>

#include "file.h"

#include "epan/conversation_table.h"

#include "epan/follow.h"

#include "capture_file.h"
#include "filter_action.h"
#include "wireshark_dialog.h"

#include <QMenu>
#include <QTreeWidgetItem>

class QCheckBox;
class QDialogButtonBox;
class QPushButton;
class QTabWidget;
class QTreeWidget;

namespace Ui {
class TrafficTableDialog;
}

class TrafficTableTreeWidgetItem : public QTreeWidgetItem
{
public:
    TrafficTableTreeWidgetItem(QTreeWidget *tree) : QTreeWidgetItem(tree)  {}
    TrafficTableTreeWidgetItem(QTreeWidget *parent, const QStringList &strings)
                   : QTreeWidgetItem (parent, strings)  {}
    virtual QVariant colData(int col, bool resolve_names) const = 0;
};

class TrafficTableTreeWidget : public QTreeWidget
{
    Q_OBJECT
public:
    explicit TrafficTableTreeWidget(QWidget *parent, register_ct_t* table);

    // String, int, or double data for each column in a row.
    // Passing -1 returns titles.
    QList<QVariant> rowData(int row) const;

    bool hasNameResolution() const;

public slots:
    void setNameResolutionEnabled(bool enable);

    // Title string plus optional count
    const QString &trafficTreeTitle() { return title_; }
    conv_hash_t* trafficTreeHash() {return &hash_;}

protected:
    register_ct_t* table_;
    QString title_;
    conv_hash_t hash_;
    bool resolve_names_;
    QMenu ctx_menu_;

    // When adding rows, resize to contents up to this number.
    int resizeThreshold() const { return 200; }
    void contextMenuEvent(QContextMenuEvent *event);

private:
    virtual void updateItems() {}

private slots:
    // Updates all items
    void updateItemsForSettingChange();

signals:
    void titleChanged(QWidget *tree, const QString &text);
    void filterAction(QString filter, FilterAction::Action action, FilterAction::ActionType type);
};

class TrafficTableDialog : public WiresharkDialog
{
    Q_OBJECT
    Q_PROPERTY(bool absolute_start_time READ absoluteStartTime)
    Q_PROPERTY(bool nanosecond_timestamps READ nanosecondTimestamps)

public:
    /** Create a new conversation window.
     *
     * @param parent Parent widget.
     * @param cf Capture file. No statistics will be calculated if this is NULL.
     * @param filter Display filter to apply.
     * @param table_name If valid, add this protocol and bring it to the front.
     */
    explicit TrafficTableDialog(QWidget &parent, CaptureFile &cf, const char *filter = NULL, const QString &table_name = tr("Unknown"));
    ~TrafficTableDialog();

    /** Use absolute start times.
     * @return true if the "Absolute start time" checkbox is checked, false otherwise.
     */
    bool absoluteStartTime();

    /** Use nanosecond timestamps.
     * @return true if the current capture file uses nanosecond timestamps, false otherwise.
     */
    bool nanosecondTimestamps() { return nanosecond_timestamps_; }

public slots:

signals:
    void filterAction(QString filter, FilterAction::Action action, FilterAction::ActionType type);
    void openFollowStreamDialog(follow_type_t type);
    void openTcpStreamGraph(int graph_type);

protected:
    Ui::TrafficTableDialog *ui;

//    CaptureFile &cap_file_;
    QString filter_;
    QMenu traffic_type_menu_;
    QPushButton *copy_bt_;
    QMap<int, TrafficTableTreeWidget *> proto_id_to_tree_;

    const QList<int> defaultProtos() const;
    static gboolean fillTypeMenuFunc(const void *key, void *value, void *userdata);
    void fillTypeMenu(QList<int> &enabled_protos);
    // Adds a conversation tree. Returns true if the tree was freshly created, false if it was cached.
    virtual bool addTrafficTable(register_ct_t*) { return false; }
    void addProgressFrame(QObject *parent);

    // UI getters
    QDialogButtonBox *buttonBox() const;
    QTabWidget *trafficTableTabWidget() const;
    QCheckBox *displayFilterCheckBox() const;
    QCheckBox *nameResolutionCheckBox() const;
    QCheckBox *absoluteTimeCheckBox() const;
    QPushButton *enabledTypesPushButton() const;

protected slots:
    virtual void currentTabChanged();
    void updateWidgets();

private:
    QString window_name_;
    bool nanosecond_timestamps_;

    QList<QVariant> curTreeRowData(int row) const;


private slots:
    void on_nameResolutionCheckBox_toggled(bool checked);
    void on_displayFilterCheckBox_toggled(bool checked);
    void setTabText(QWidget *tree, const QString &text);
    void toggleTable();
    void captureEvent(CaptureEvent e);

    void copyAsCsv();
    void copyAsYaml();
    virtual void on_buttonBox_helpRequested() = 0;
};

#endif // TRAFFIC_TABLE_DIALOG_H
