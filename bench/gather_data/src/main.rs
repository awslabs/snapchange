use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use snapchange::GlobalStats;
use tokio::io;

#[derive(Debug, PartialOrd, PartialEq)]
struct Data {
    pages: u32,
    instrs: u32,
    breakpoints: u32,
    cores: u32,
    exec_per_sec: f32,
    total_exec_per_sec: f32,
}

async fn gather_data(entry: PathBuf) -> io::Result<Data> {
    // Read the toml file
    let data = tokio::fs::read_to_string(&entry).await?;

    // Read the data as the toml
    println!("{entry:?}");
    let data: GlobalStats = toml::from_str(&data).unwrap();

    let mut single_core_sum = 0.0;
    let mut total_sum = 0.0;

    // Parse the filename for pages, instrs, and cores for
    let mut filename = entry.file_name().unwrap().to_str().unwrap().split("-");
    let pages = filename
        .next()
        .unwrap()
        .split("_")
        .nth(1)
        .unwrap()
        .parse()
        .unwrap();
    let instrs = filename
        .next()
        .unwrap()
        .split("_")
        .nth(1)
        .unwrap()
        .parse()
        .unwrap();
    let cores = filename
        .next()
        .unwrap()
        .split("_")
        .nth(1)
        .unwrap()
        .parse()
        .unwrap();

    let exec_per_sec = data.exec_per_sec as f32 / cores as f32;
    let total_exec_per_sec = data.exec_per_sec as f32;

    // The instrs data point is also used when testing breakpoints. If the filename has instrs,
    // then use the instrs variable as instrs. Otherwise, use the instrs variable as breakpoints
    let (instrs, breakpoints) = if entry.to_str().unwrap().contains(&"instrs") {
        (instrs, 0)
    } else {
        (0, instrs)
    };

    Ok(Data {
        pages,
        instrs,
        cores,
        breakpoints,
        exec_per_sec,
        total_exec_per_sec,
    })
}

// const PAGES: &[u32] = &[100, 500, 1000, 5000, 10000, 25000, 50000, 100000];
const PAGES: &[u32] = &[100, 1000, 10000, 25000];
const INSTRS: &[u32] = &[100_000, 1_000_000, 100_000_000, 1_000_000_000];
const CORES: &[u32] = &[1, 2, 4, 8, 16, 32, 64, 92, 128, 164, 192];

#[tokio::main]
async fn main() -> io::Result<()> {
    let dir = std::env::args().nth(1).expect("USAGE: <data dir>");

    let mut res = Vec::new();
    // let mut data = BTreeMap::new();

    let mut cores_exec = Vec::new();
    let mut pages_exec = Vec::new();
    let mut instrs_exec = Vec::new();
    let mut breakpoints_exec = Vec::new();

    let mut entries = tokio::fs::read_dir(&dir).await?;
    while let Some(entry) = entries.next_entry().await? {
        let data = gather_data(entry.path()).await?;

        if let Data {
            pages: 100,
            instrs: 1000000,
            breakpoints,
            cores,
            exec_per_sec,
            total_exec_per_sec,
        } = data
        {
            cores_exec.push((cores, exec_per_sec));
        }

        if let Data {
            pages,
            instrs: 1000000,
            cores: 8,
            breakpoints,
            exec_per_sec,
            total_exec_per_sec,
        } = data
        {
            pages_exec.push((pages, exec_per_sec));
        }

        if let Data {
            pages: 100,
            instrs,
            cores: 8,
            breakpoints,
            exec_per_sec,
            total_exec_per_sec,
        } = data
        {
            if entry.path().to_str().unwrap().contains(&"instrs") {
                instrs_exec.push((instrs, exec_per_sec));
            } else {
                breakpoints_exec.push((instrs, exec_per_sec));
            }
        }

        res.push(data);
    }

    res.sort_by(|a, b| {
        (a.pages, a.instrs, a.breakpoints, a.cores)
            .partial_cmp(&(b.pages, b.instrs, b.breakpoints, b.cores))
            .unwrap()
    });

    let mut file_plots = Vec::new();

    // Create the output dataplots directory
    let dataplots = Path::new("dataplots");
    let internal_data = dataplots.join("data");
    if dataplots.exists() {
        tokio::fs::remove_dir_all(&dataplots).await?;
    }

    tokio::fs::create_dir(&dataplots).await?;
    tokio::fs::create_dir(&internal_data).await?;

    for page in PAGES {
        for instr in INSTRS {
            let mut curr_data = Vec::new();
            for data in &res {
                let Data {
                    pages,
                    instrs,
                    breakpoints,
                    cores,
                    exec_per_sec,
                    total_exec_per_sec,
                } = data;
                if pages == page && instrs == instr && *exec_per_sec > 0.0 {
                    curr_data.push(format!("{cores} {exec_per_sec}"));
                }
            }

            let instr = if instr >= &1_000_000_000 {
                format!("{}G", instr / 1_000_000_000)
            } else if instr >= &1_000_000 {
                format!("{}M", instr / 1_000_000)
            } else if instr >= &1_000 {
                format!("{}K", instr / 1_000)
            } else {
                format!("{instr}")
            };

            let page = if page >= &1_000_000 {
                format!("{}M", page / 1_000_000)
            } else if page >= &1_000 {
                format!("{}K", page / 1_000)
            } else {
                format!("{page}")
            };

            let filename = format!("data_page_{page}_instrs_{instr}.dat");
            if !curr_data.is_empty() {
                file_plots.push(format!("'data/{filename}' with linespoints"));
                tokio::fs::write(internal_data.join(&filename), curr_data.join("\n")).await?;
            }
        }
    }

    for page in PAGES {
        for breakpoint in INSTRS {
            let mut curr_data = Vec::new();
            for data in &res {
                let Data {
                    pages,
                    instrs,
                    breakpoints,
                    cores,
                    exec_per_sec,
                    total_exec_per_sec,
                } = data;
                if pages == page && breakpoints == breakpoints && *exec_per_sec > 0.0 {
                    curr_data.push(format!("{cores} {exec_per_sec}"));
                }
            }

            let breakpoint = if breakpoint >= &1_000_000_000 {
                format!("{}G", breakpoint / 1_000_000_000)
            } else if breakpoint >= &1_000_000 {
                format!("{}M", breakpoint / 1_000_000)
            } else if breakpoint >= &1_000 {
                format!("{}K", breakpoint / 1_000)
            } else {
                format!("{breakpoint}")
            };

            let page = if page >= &1_000_000 {
                format!("{}M", page / 1_000_000)
            } else if page >= &1_000 {
                format!("{}K", page / 1_000)
            } else {
                format!("{page}")
            };

            let filename = format!("data_page_{page}_breakpoints_{breakpoint}.dat");
            if !curr_data.is_empty() {
                file_plots.push(format!("'data/{filename}' with linespoints"));
                tokio::fs::write(internal_data.join(&filename), curr_data.join("\n")).await?;
            }
        }
    }

    let mut plot = String::new();
    plot.push_str("set terminal svg size 1400,900\n");
    plot.push_str("set title \"Number of cores used x Exec/sec/core\"\n");
    plot.push_str("set xlabel \"Cores\"\n");
    plot.push_str("set ylabel \"Exec / sec / core\"\n");
    plot.push_str("set logscale y\n");
    plot.push_str("set output \"plot_cores.svg\"\n");
    plot.push_str("plot ");
    plot.push_str(&file_plots.join(", \\\n"));
    plot.push('\n');
    tokio::fs::write(dataplots.join("plot_cores.plot"), plot).await?;

    file_plots.clear();
    for core in CORES {
        for instr in INSTRS {
            let mut curr_data = Vec::new();
            for data in &res {
                let Data {
                    pages,
                    instrs,
                    breakpoints,
                    cores,
                    exec_per_sec,
                    total_exec_per_sec,
                } = data;
                if core == cores && instrs == instr && *exec_per_sec > 0.0 && pages <= &30000 {
                    curr_data.push(format!("{pages} {exec_per_sec}"));
                }
            }

            let instr = if instr >= &1_000_000 {
                format!("{}M", instr / 1_000_000)
            } else if instr >= &1_000 {
                format!("{}K", instr / 1_000)
            } else {
                format!("{instr}")
            };

            let filename = format!("data_core_{core}_instrs_{instr}.dat");
            if !curr_data.is_empty() {
                file_plots.push(format!("'data/{filename}' with linespoints"));
                tokio::fs::write(internal_data.join(&filename), curr_data.join("\n")).await?;
            }
        }
    }

    let mut plot = String::new();
    plot.push_str("set terminal svg size 1400,900\n");
    plot.push_str("set title \"Number of dirty pages per reset x Exec/sec/core\"\n");
    plot.push_str("set xlabel \"Dirty pages / reset\"\n");
    plot.push_str("set ylabel \"Exec / sec / core\"\n");
    plot.push_str("set logscale x\n");
    plot.push_str("set output \"plot_pages.svg\"\n");
    plot.push_str("plot ");
    plot.push_str(&file_plots.join(", \\\n"));
    plot.push('\n');
    tokio::fs::write(dataplots.join("plot_pages.plot"), plot).await?;

    file_plots.clear();
    for core in CORES {
        for page in PAGES {
            let mut curr_data = Vec::new();
            for data in &res {
                let Data {
                    pages,
                    instrs,
                    cores,
                    breakpoints,
                    exec_per_sec,
                    total_exec_per_sec,
                } = data;
                if core == cores
                    && pages == page
                    && *exec_per_sec > 0.0
                    && pages <= &30000
                    && *instrs > 1
                {
                    curr_data.push(format!("{instrs} {exec_per_sec}"));
                }
            }

            let page = if page >= &1_000_000 {
                format!("{}M", page / 1_000_000)
            } else if page >= &1_000 {
                format!("{}K", page / 1_000)
            } else {
                format!("{page}")
            };

            let filename = format!("data_core_{core}_pages_{page}.dat");
            if !curr_data.is_empty() {
                file_plots.push(format!("'data/{filename}' with linespoints"));
                tokio::fs::write(internal_data.join(&filename), curr_data.join("\n")).await?;
            }
        }
    }

    let mut plot = String::new();
    plot.push_str("set terminal svg size 1400,900\n");
    plot.push_str("set title \"Number of executed instructions per fuzz case x Exec/sec/core\"\n");
    plot.push_str("set xlabel \"Executed instructions per fuzz case\"\n");
    plot.push_str("set ylabel \"Exec / sec / core\"\n");
    plot.push_str("set logscale x\n");
    plot.push_str("set output \"plot_instrs.svg\"\n");
    plot.push_str("plot ");
    plot.push_str(&file_plots.join(", \\\n"));
    plot.push('\n');
    tokio::fs::write(dataplots.join("plot_instrs.plot"), plot).await?;

    // Write out the sorted output data
    let mut outdata = String::new();
    outdata.push_str("pages,instrs,bps,cores,exec_sec_core,exec_sec\n");
    for Data {
        pages,
        instrs,
        breakpoints,
        cores,
        mut exec_per_sec,
        total_exec_per_sec,
    } in res
    {
        if exec_per_sec.is_nan() || exec_per_sec.is_infinite() {
            exec_per_sec = 0.0
        }

        outdata.push_str(&format!(
            "{pages},{instrs},{breakpoints},{cores},{exec_per_sec:.4},{total_exec_per_sec}\n"
        ));
    }

    let outfile = format!("{dir}.dat");
    println!("Writing output data to {outfile}");
    tokio::fs::write(outfile, outdata).await?;

    Ok(())
}
