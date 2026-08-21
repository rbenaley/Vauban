//! Cursor pagination helpers for full-table scans (not SSR `?page=N`).

use toasty::Db;
use toasty::schema::Load;
use toasty::stmt::Page;

/// Default batch for seed / export / resync / purge jobs.
pub const SCAN_PAGE_SIZE: usize = 256;

/// Take the current page's items and fetch `page.next` (if any).
///
/// End of list is `None`, not `items.len() < per_page`. Do not build the
/// starting page from a query that already has `.limit()` / `.offset()`.
pub async fn advance_scan_page<M: Load<Output = M>>(
    mut page: Page<M>,
    db: &mut Db,
) -> anyhow::Result<(Vec<M>, Option<Page<M>>)> {
    let items = std::mem::take(&mut page.items);
    let next = page.next(db).await?;
    Ok((items, next))
}
