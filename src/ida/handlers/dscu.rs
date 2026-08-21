//! Native IDA 9.4 dyld_shared_cache helpers.

use crate::error::ToolError;
use crate::ida::types::{DscImageInfo, DscRegionInfo};
use idalib::IDB;

fn require_dscu(idb: &Option<IDB>) -> Result<(), ToolError> {
    idb.as_ref().ok_or(ToolError::NoDatabaseOpen)?;
    if idalib::dscu::is_available() {
        Ok(())
    } else {
        Err(ToolError::NotSupported(
            "IDA dscu service is not available for the current database; open a dyld_shared_cache with IDA 9.4+ first"
                .to_string(),
        ))
    }
}

fn hex_addr(addr: u64) -> String {
    format!("0x{addr:x}")
}

fn image_info(info: idalib::dscu::ImageInfo) -> DscImageInfo {
    DscImageInfo {
        index: info.index,
        name: info.name,
        file_name: info.file_name,
        address: hex_addr(info.address),
        address_value: info.address,
        total_size: info.total_size,
        file_index: info.file_index,
        loaded: info.loaded,
    }
}

fn region_kind(kind: idalib::dscu::RegionKind) -> String {
    let kind = match kind {
        idalib::dscu::RegionKind::ImageEntity => "image_entity",
        idalib::dscu::RegionKind::Island => "island",
        idalib::dscu::RegionKind::Header => "header",
        idalib::dscu::RegionKind::Mapping => "mapping",
        idalib::dscu::RegionKind::Unknown => "unknown",
        idalib::dscu::RegionKind::Got => "got",
        idalib::dscu::RegionKind::CacheData => "cache_data",
        idalib::dscu::RegionKind::Invalid(raw) => return format!("invalid({raw})"),
    };
    kind.to_string()
}

fn region_info(info: idalib::dscu::RegionInfo) -> DscRegionInfo {
    DscRegionInfo {
        start: hex_addr(info.start),
        start_value: info.start,
        size: info.size,
        kind: region_kind(info.kind),
        image_index: info.image_index,
        name: info.name,
        loaded: info.loaded,
    }
}

pub fn handle_dsc_load_image(idb: &Option<IDB>, module: &str) -> Result<DscImageInfo, ToolError> {
    require_dscu(idb)?;
    idalib::dscu::load_image(module)
        .map(image_info)
        .map_err(ToolError::from)
}

pub fn handle_dsc_load_region(idb: &Option<IDB>, ea: u64) -> Result<DscRegionInfo, ToolError> {
    require_dscu(idb)?;
    idalib::dscu::load_region(ea)
        .map(region_info)
        .map_err(ToolError::from)
}
