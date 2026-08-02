//! SQL-backed loaders for admin companies list + search shard.

use std::collections::{HashMap, HashSet};

use toasty::Db;

use crate::{
    id_lookups::users_by_ids,
    list_page::{COMPANIES_PAGE_SIZE, clamp_page, page_count, page_offset},
    models::{Membership, Organization, RESERVED_ORG_SLUG, User},
    sql_search::ilike_contains,
};

#[derive(Clone)]
pub(super) struct CompanyCard {
    pub(super) org: Organization,
    pub(super) emails: Vec<String>,
}

async fn hydrate_cards(db: &mut Db, orgs: Vec<Organization>) -> anyhow::Result<Vec<CompanyCard>> {
    if orgs.is_empty() {
        return Ok(Vec::new());
    }
    let org_ids: Vec<u64> = orgs.iter().map(|o| o.id).collect();
    let memberships = Membership::all()
        .filter(Membership::fields().organization_id().in_list(org_ids))
        .exec(db)
        .await?;
    let user_ids: Vec<u64> = memberships.iter().map(|m| m.user_id).collect();
    let users = users_by_ids(db, &user_ids).await?;
    let user_by_id: HashMap<u64, &User> = users.iter().map(|u| (u.id, u)).collect();

    let mut cards = Vec::with_capacity(orgs.len());
    for org in orgs {
        let mut emails: Vec<String> = memberships
            .iter()
            .filter(|m| m.organization_id == org.id)
            .filter_map(|m| user_by_id.get(&m.user_id).map(|u| u.email.clone()))
            .collect();
        emails.sort();
        cards.push(CompanyCard { org, emails });
    }
    Ok(cards)
}

/// Org ids matching non-empty search `q` (field ilike OR account email ilike).
async fn search_org_ids(db: &mut Db, q: &str) -> anyhow::Result<Vec<u64>> {
    let Some(pat) = ilike_contains(q) else {
        return Ok(Vec::new());
    };

    let field_hits = Organization::all()
        .filter(
            Organization::fields()
                .slug()
                .ne(RESERVED_ORG_SLUG.to_owned()),
        )
        .filter(
            Organization::fields()
                .name()
                .ilike_with_escape(pat.clone(), '\\')
                .or(Organization::fields()
                    .slug()
                    .ilike_with_escape(pat.clone(), '\\'))
                .or(Organization::fields()
                    .technical_contact_name()
                    .ilike_with_escape(pat.clone(), '\\'))
                .or(Organization::fields()
                    .technical_contact_email()
                    .ilike_with_escape(pat.clone(), '\\'))
                .or(Organization::fields()
                    .vat()
                    .ilike_with_escape(pat.clone(), '\\'))
                .or(Organization::fields()
                    .address()
                    .ilike_with_escape(pat.clone(), '\\')),
        )
        .exec(db)
        .await?;

    let mut ids: HashSet<u64> = field_hits.into_iter().map(|o| o.id).collect();

    let email_users = User::all()
        .filter(User::fields().email().ilike_with_escape(pat, '\\'))
        .exec(db)
        .await?;
    let user_ids: Vec<u64> = email_users.into_iter().map(|u| u.id).collect();
    if !user_ids.is_empty() {
        let memberships = Membership::all()
            .filter(Membership::fields().user_id().in_list(user_ids))
            .exec(db)
            .await?;
        for m in memberships {
            ids.insert(m.organization_id);
        }
    }

    let id_list: Vec<u64> = ids.into_iter().collect();
    if id_list.is_empty() {
        return Ok(Vec::new());
    }
    let orgs = Organization::all()
        .filter(Organization::fields().id().in_list(id_list))
        .exec(db)
        .await?;
    Ok(orgs
        .into_iter()
        .filter(|o| !o.slug.eq_ignore_ascii_case(RESERVED_ORG_SLUG))
        .map(|o| o.id)
        .collect())
}

/// Count + one page of company cards for admin list/shard.
pub(super) async fn load_company_cards_page(
    db: &mut Db,
    q: &str,
    page: usize,
) -> anyhow::Result<(Vec<CompanyCard>, usize)> {
    if q.is_empty() {
        let total = Organization::all()
            .filter(
                Organization::fields()
                    .slug()
                    .ne(RESERVED_ORG_SLUG.to_owned()),
            )
            .count()
            .exec(db)
            .await? as usize;
        let pages = page_count(total, COMPANIES_PAGE_SIZE);
        let page = clamp_page(page, pages);
        let orgs = Organization::all()
            .filter(
                Organization::fields()
                    .slug()
                    .ne(RESERVED_ORG_SLUG.to_owned()),
            )
            .order_by(Organization::fields().name().asc())
            .limit(COMPANIES_PAGE_SIZE)
            .offset(page_offset(page, COMPANIES_PAGE_SIZE))
            .exec(db)
            .await?;
        let cards = hydrate_cards(db, orgs).await?;
        return Ok((cards, total));
    }

    let ids = search_org_ids(db, q).await?;
    let mut orgs = if ids.is_empty() {
        Vec::new()
    } else {
        Organization::all()
            .filter(Organization::fields().id().in_list(ids))
            .exec(db)
            .await?
    };
    orgs.sort_by(|a, b| {
        a.name
            .to_lowercase()
            .cmp(&b.name.to_lowercase())
            .then_with(|| a.id.cmp(&b.id))
    });
    let total = orgs.len();
    let pages = page_count(total, COMPANIES_PAGE_SIZE);
    let page = clamp_page(page, pages);
    let start = page_offset(page, COMPANIES_PAGE_SIZE);
    let end = (start + COMPANIES_PAGE_SIZE).min(total);
    let page_orgs = if start >= total {
        Vec::new()
    } else {
        orgs[start..end].to_vec()
    };
    let cards = hydrate_cards(db, page_orgs).await?;
    Ok((cards, total))
}

/// Load a single company card by id (delete overlay).
pub(super) async fn load_company_card_by_id(
    db: &mut Db,
    id: u64,
) -> anyhow::Result<Option<CompanyCard>> {
    let org = Organization::all()
        .filter(Organization::fields().id().eq(id))
        .limit(1)
        .exec(db)
        .await?
        .into_iter()
        .next();
    let Some(org) = org else {
        return Ok(None);
    };
    if org.slug.eq_ignore_ascii_case(RESERVED_ORG_SLUG) {
        return Ok(None);
    }
    let mut cards = hydrate_cards(db, vec![org]).await?;
    Ok(cards.pop())
}
