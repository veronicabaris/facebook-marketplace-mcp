// Known GraphQL doc_ids for Facebook Marketplace.
// These are hashed operation identifiers that Facebook rotates on deploys.
// Run `npm run capture-queries` to discover current values if these break.

export const MARKETPLACE_SEARCH_DOC_ID = "27212616558440397";
export const LOCATION_SEARCH_DOC_ID = "5585904654783609";

// Listing detail uses a different approach — we extract the doc_id dynamically
// or fall back to fetching the listing page and parsing embedded data.
export let LISTING_DETAIL_DOC_ID = "";

export function setListingDetailDocId(docId: string) {
  LISTING_DETAIL_DOC_ID = docId;
}

export function buildSearchVariables(params: {
  query: string;
  latitude: number;
  longitude: number;
  radiusKm: number;
  minPrice?: number;
  maxPrice?: number;
  category?: string;
  limit: number;
  cursor?: string;
}) {
  // Shape captured live from CometMarketplaceSearchContentPaginationQuery.
  // The Relay provider flag is a *required* variable — omitting it triggers
  // "missing_required_variable_value" and an empty result.
  const browseParams: Record<string, unknown> = {
    commerce_enable_local_pickup: true,
    commerce_enable_shipping: true,
    commerce_search_and_rp_available: true,
    commerce_search_and_rp_category_id: params.category ? [params.category] : [],
    commerce_search_and_rp_condition: null,
    commerce_search_and_rp_ctime_days: null,
    filter_location_latitude: params.latitude,
    filter_location_longitude: params.longitude,
    filter_price_lower_bound:
      params.minPrice != null ? Math.round(params.minPrice * 100) : 0,
    filter_price_upper_bound:
      params.maxPrice != null ? Math.round(params.maxPrice * 100) : 214748364700,
    filter_radius_km: params.radiusKm,
  };

  const variables: Record<string, unknown> = {
    count: params.limit,
    cursor: params.cursor ?? null,
    params: {
      bqf: {
        callsite: "COMMERCE_MKTPLACE_WWW",
        query: params.query,
      },
      browse_request_params: browseParams,
      custom_request_params: {
        browse_context: null,
        contextual_filters: [],
        referral_code: null,
        referral_ui_component: null,
        saved_search_strid: null,
        search_vertical: "C2C",
        seo_url: null,
        serp_landing_settings: {
          virtual_category_id: "",
        },
        surface: "SEARCH",
        virtual_contextual_filters: [],
      },
    },
    scale: 1,
    __relay_internal__pv__GHLShouldChangeMarketplaceSponsoredDataFieldNamerelayprovider:
      true,
  };

  return variables;
}

export function buildLocationSearchVariables(query: string) {
  return {
    params: {
      caller: "MARKETPLACE",
      page_category: ["CITY", "SUBCITY", "NEIGHBORHOOD"],
      query,
    },
  };
}
